#![forbid(unsafe_code)]

//! NTLM authentication helpers for the MS-TSGU HTTP Transport.
//!
//! RD Gateway uses HTTP challenge/response authentication on both the
//! IN and OUT channels. The client sends the initial request, the
//! gateway replies `HTTP/1.1 401 Unauthorized` with `WWW-Authenticate:
//! NTLM <base64>` (or `Negotiate`), and the client retries with
//! `Authorization: NTLM <base64>` carrying either an NTLMSSP Negotiate
//! or Authenticate message.
//!
//! This module reuses the NTLMv2 primitives from `justrdp-pdu::ntlm`
//! (which also back the CredSSP implementation) and wraps them in an
//! HTTP-oriented [`NtlmClient`] state machine plus base64 and header
//! helpers. It is transport-agnostic — the caller owns the HTTP
//! request/response loop.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::encode_vec;
use justrdp_pdu::ntlm::compute::{
    compute_mic, compute_response, key_exchange_encrypt, modify_target_info, ntowfv2,
};
use justrdp_pdu::ntlm::messages::{
    to_utf16le, AuthenticateMessage, AvId, AvPair, ChallengeMessage, NegotiateFlags,
    NegotiateMessage, NtlmVersion,
};

// =============================================================================
// Credentials / random material
// =============================================================================

/// Credentials to authenticate with the gateway.
///
/// `domain` may be empty; if so the client falls back to the server's
/// `MsvAvNbDomainName` from target_info per MS-NLMP 3.1.5.1.2.
/// `workstation` is optional and typically blank for HTTP clients.
#[derive(Debug, Clone)]
pub struct NtlmCredentials {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub workstation: String,
}

impl NtlmCredentials {
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        domain: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            domain: domain.into(),
            workstation: String::new(),
        }
    }
}

/// Random material supplied by the caller.
///
/// These MUST be cryptographically random for each new NTLM exchange.
/// The gateway crate does not pull in an RNG — callers are expected to
/// obtain entropy from their host environment (e.g. `getrandom` on
/// std).
#[derive(Debug, Clone, Copy)]
pub struct NtlmRandom {
    /// 8-byte NTLMv2 client challenge.
    pub client_challenge: [u8; 8],
    /// 16-byte key encrypted and sent to the server via the
    /// `EncryptedRandomSessionKey` field of the Authenticate message.
    pub exported_session_key: [u8; 16],
}

// =============================================================================
// HTTP auth scheme
// =============================================================================

/// HTTP authentication scheme used on the `Authorization` and
/// `WWW-Authenticate` header lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    /// Raw NTLMSSP bytes, the most common RD Gateway scheme.
    Ntlm,
    /// SPNEGO-wrapped NTLMSSP or Kerberos. The caller is responsible
    /// for wrapping / unwrapping the SPNEGO token around the raw NTLM
    /// bytes this module produces and consumes.
    Negotiate,
}

impl AuthScheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ntlm => "NTLM",
            Self::Negotiate => "Negotiate",
        }
    }
}

// =============================================================================
// NtlmClient state machine
// =============================================================================

/// State of the NTLM HTTP auth exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtlmAuthState {
    /// Ready to produce the initial NEGOTIATE (type 1) message.
    Initial,
    /// NEGOTIATE has been produced; waiting for the server's CHALLENGE
    /// (type 2) via [`NtlmClient::authenticate`].
    WaitChallenge,
    /// AUTHENTICATE (type 3) has been produced; the exchange is done.
    Done,
}

/// Errors produced by [`NtlmClient`].
#[derive(Debug)]
pub enum NtlmError {
    /// Method called in a state that does not accept it (e.g.
    /// `authenticate` before `negotiate`).
    InvalidState(&'static str),
    /// Failed to decode the server CHALLENGE bytes.
    BadChallenge,
    /// Failed to parse `target_info` AV pairs in the CHALLENGE.
    BadTargetInfo,
    /// Failed to encode the AUTHENTICATE message (field length > u16).
    Encode,
}

/// NTLMv2 HTTP auth client — produces raw NTLMSSP bytes for the
/// Authorization header.
///
/// The flow is:
///
/// 1. [`Self::negotiate`] produces the NEGOTIATE bytes. Send them in
///    `Authorization: NTLM <base64>`.
/// 2. The server responds with `401` and `WWW-Authenticate: NTLM
///    <base64-challenge>`. Extract the raw bytes with
///    [`parse_www_authenticate`].
/// 3. [`Self::authenticate`] consumes the CHALLENGE and produces the
///    AUTHENTICATE bytes. Send them in the retry request.
#[derive(Debug, Clone)]
pub struct NtlmClient {
    creds: NtlmCredentials,
    random: NtlmRandom,
    state: NtlmAuthState,
    /// Cached raw bytes of the NEGOTIATE message — needed as input to
    /// the MIC computation in step 3.
    negotiate_bytes: Vec<u8>,
}

impl NtlmClient {
    pub fn new(creds: NtlmCredentials, random: NtlmRandom) -> Self {
        Self {
            creds,
            random,
            state: NtlmAuthState::Initial,
            negotiate_bytes: Vec::new(),
        }
    }

    pub fn state(&self) -> NtlmAuthState {
        self.state
    }

    /// Produce the NTLMSSP NEGOTIATE (type 1) message.
    pub fn negotiate(&mut self) -> Result<Vec<u8>, NtlmError> {
        if self.state != NtlmAuthState::Initial {
            return Err(NtlmError::InvalidState("negotiate called twice"));
        }
        let msg = NegotiateMessage::new();
        let bytes = encode_vec(&msg).map_err(|_| NtlmError::Encode)?;
        self.negotiate_bytes = bytes.clone();
        self.state = NtlmAuthState::WaitChallenge;
        Ok(bytes)
    }

    /// Consume the server's CHALLENGE and produce the NTLMSSP
    /// AUTHENTICATE (type 3) message.
    pub fn authenticate(&mut self, challenge_bytes: &[u8]) -> Result<Vec<u8>, NtlmError> {
        if self.state != NtlmAuthState::WaitChallenge {
            return Err(NtlmError::InvalidState(
                "authenticate called without preceding negotiate",
            ));
        }

        let challenge = ChallengeMessage::decode_from_bytes(challenge_bytes)
            .map_err(|_| NtlmError::BadChallenge)?;

        // MS-NLMP 3.1.5.1.2: if the client passed an empty domain, use
        // the server's NbDomainName from target_info.
        let av_pairs = AvPair::parse_list(&challenge.target_info)
            .map_err(|_| NtlmError::BadTargetInfo)?;
        let effective_domain: String = if self.creds.domain.is_empty() {
            if let Some(nb) = AvPair::find(&av_pairs, AvId::MsvAvNbDomainName) {
                utf16le_to_string(&nb.value)
            } else {
                String::new()
            }
        } else {
            self.creds.domain.clone()
        };

        // Prefer the server-supplied MsvAvTimestamp over a local clock.
        let has_timestamp = av_pairs.iter().any(|p| p.id == AvId::MsvAvTimestamp as u16);
        let time = AvPair::find(&av_pairs, AvId::MsvAvTimestamp)
            .and_then(|ts| {
                if ts.value.len() == 8 {
                    Some(u64::from_le_bytes(ts.value[..8].try_into().unwrap()))
                } else {
                    None
                }
            })
            .unwrap_or(0);

        let response_key = ntowfv2(&self.creds.password, &self.creds.username, &effective_domain);
        let modified_target_info = modify_target_info(&challenge.target_info);

        let (nt_response, lm_response, session_base_key) = compute_response(
            &response_key,
            &challenge.server_challenge,
            &self.random.client_challenge,
            time,
            &modified_target_info,
            has_timestamp,
        );

        let encrypted_random_session_key =
            key_exchange_encrypt(&session_base_key, &self.random.exported_session_key);

        // Negotiate flags: AND client defaults with server flags so we
        // advertise only what the server granted.
        let negotiated_flags = NegotiateFlags::from_bits(
            NegotiateFlags::client_default().bits() & challenge.flags.bits(),
        );

        let mut authenticate = AuthenticateMessage {
            flags: negotiated_flags,
            lm_response,
            nt_response,
            domain_name: to_utf16le(&effective_domain),
            user_name: to_utf16le(&self.creds.username),
            workstation: to_utf16le(&self.creds.workstation),
            encrypted_random_session_key,
            version: NtlmVersion::windows_10(),
            mic: [0u8; 16],
        };

        // MIC = HMAC_MD5(exported_session_key,
        //                negotiate || challenge || auth_with_zeroed_mic)
        let zeroed_mic_bytes = authenticate.to_bytes().map_err(|_| NtlmError::Encode)?;
        let mic = compute_mic(
            &self.random.exported_session_key,
            &self.negotiate_bytes,
            challenge_bytes,
            &zeroed_mic_bytes,
        );
        authenticate.mic = mic;

        let bytes = authenticate.to_bytes().map_err(|_| NtlmError::Encode)?;
        self.state = NtlmAuthState::Done;
        Ok(bytes)
    }
}

fn utf16le_to_string(bytes: &[u8]) -> String {
    bytes
        .chunks_exact(2)
        .filter_map(|c| {
            let ch = u16::from_le_bytes([c[0], c[1]]);
            char::from_u32(ch as u32)
        })
        .collect()
}

// =============================================================================
// HTTP header helpers
// =============================================================================

/// Build the value for an `Authorization` header: `"NTLM <base64>"`.
pub fn build_authorization_header(scheme: AuthScheme, raw: &[u8]) -> String {
    let mut s = String::with_capacity(scheme.as_str().len() + 1 + raw.len() * 4 / 3 + 4);
    s.push_str(scheme.as_str());
    s.push(' ');
    s.push_str(&base64_encode(raw));
    s
}

/// Parse a `WWW-Authenticate` header value and return the decoded
/// server token bytes, or `None` if the scheme does not match or the
/// value is malformed.
///
/// Accepts multiple whitespace between the scheme and the token and
/// performs case-insensitive scheme matching. If the header contains
/// just the scheme name (e.g. `"NTLM"` with no token), returns
/// `Some(vec![])` — this is how servers advertise that they accept
/// the scheme without yet sending a challenge.
pub fn parse_www_authenticate(header_value: &str, scheme: AuthScheme) -> Option<Vec<u8>> {
    let trimmed = header_value.trim();
    let scheme_name = scheme.as_str();
    if trimmed.len() < scheme_name.len() {
        return None;
    }
    let (head, tail) = trimmed.split_at(scheme_name.len());
    if !head.eq_ignore_ascii_case(scheme_name) {
        return None;
    }
    let tail = tail.trim_start();
    if tail.is_empty() {
        return Some(Vec::new());
    }
    // Stop at first comma (multi-challenge header) or whitespace/end.
    let end = tail.find(|c: char| c == ',' || c.is_whitespace()).unwrap_or(tail.len());
    base64_decode(&tail[..end])
}

// =============================================================================
// Base64 (RFC 4648 §4, standard alphabet with padding)
// =============================================================================

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `bytes` as RFC 4648 standard base64 (with `=` padding).
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for c in chunks.by_ref() {
        let n = ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | (c[2] as u32);
        out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[(n & 0x3F) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push(BASE64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

/// Decode a standard base64 string (RFC 4648 §4). Returns `None` on
/// any invalid character, bad length, or bad padding.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    // Strip trailing whitespace but do not accept internal whitespace.
    let s = s.trim();
    if s.is_empty() {
        return Some(Vec::new());
    }
    if s.len() % 4 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = decode_char(bytes[i])?;
        let b1 = decode_char(bytes[i + 1])?;
        let (b2, pad2) = decode_char_or_pad(bytes[i + 2])?;
        let (b3, pad3) = decode_char_or_pad(bytes[i + 3])?;
        // Padding is only legal at the very end.
        if (pad2 || pad3) && i + 4 != bytes.len() {
            return None;
        }
        if pad2 && !pad3 {
            return None;
        }
        let n = ((b0 as u32) << 18) | ((b1 as u32) << 12) | ((b2 as u32) << 6) | (b3 as u32);
        out.push(((n >> 16) & 0xFF) as u8);
        if !pad2 {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if !pad3 {
            out.push((n & 0xFF) as u8);
        }
        i += 4;
    }
    Some(out)
}

fn decode_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn decode_char_or_pad(c: u8) -> Option<(u8, bool)> {
    if c == b'=' {
        Some((0, true))
    } else {
        decode_char(c).map(|v| (v, false))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- Base64 ----------

    // RFC 4648 §10 test vectors (standard alphabet).
    #[test]
    fn base64_rfc4648_test_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, encoded) in cases {
            assert_eq!(base64_encode(raw), *encoded, "encode {:?}", raw);
            assert_eq!(base64_decode(encoded).as_deref(), Some(*raw), "decode {}", encoded);
        }
    }

    #[test]
    fn base64_rejects_bad_input() {
        assert!(base64_decode("abc").is_none()); // length not multiple of 4
        assert!(base64_decode("@@@@").is_none()); // invalid char
        assert!(base64_decode("Z===").is_none()); // pad at offset 1
        assert!(base64_decode("Zm==Zm==").is_none()); // pad in middle
    }

    #[test]
    fn base64_roundtrip_random_bytes() {
        let data: Vec<u8> = (0..=255u8).collect();
        let s = base64_encode(&data);
        assert_eq!(base64_decode(&s).unwrap(), data);
    }

    // ---------- Authorization / WWW-Authenticate headers ----------

    #[test]
    fn build_authorization_header_ntlm() {
        let v = build_authorization_header(AuthScheme::Ntlm, b"foo");
        assert_eq!(v, "NTLM Zm9v");
    }

    #[test]
    fn build_authorization_header_negotiate() {
        let v = build_authorization_header(AuthScheme::Negotiate, b"foobar");
        assert_eq!(v, "Negotiate Zm9vYmFy");
    }

    #[test]
    fn parse_www_authenticate_ntlm_with_token() {
        let v = parse_www_authenticate("NTLM Zm9v", AuthScheme::Ntlm);
        assert_eq!(v, Some(b"foo".to_vec()));
    }

    #[test]
    fn parse_www_authenticate_case_insensitive() {
        assert_eq!(
            parse_www_authenticate("ntlm Zm9v", AuthScheme::Ntlm),
            Some(b"foo".to_vec())
        );
        assert_eq!(
            parse_www_authenticate("NegOtIAte Zm9v", AuthScheme::Negotiate),
            Some(b"foo".to_vec())
        );
    }

    #[test]
    fn parse_www_authenticate_without_token_returns_empty() {
        assert_eq!(
            parse_www_authenticate("NTLM", AuthScheme::Ntlm),
            Some(Vec::new())
        );
        assert_eq!(
            parse_www_authenticate("NTLM   ", AuthScheme::Ntlm),
            Some(Vec::new())
        );
    }

    #[test]
    fn parse_www_authenticate_wrong_scheme() {
        assert_eq!(parse_www_authenticate("Basic Zm9v", AuthScheme::Ntlm), None);
        assert_eq!(
            parse_www_authenticate("NTLM Zm9v", AuthScheme::Negotiate),
            None
        );
    }

    #[test]
    fn parse_www_authenticate_stops_at_comma() {
        // Some servers return multi-scheme challenges separated by commas.
        let v = parse_www_authenticate("NTLM Zm9v, Basic realm=x", AuthScheme::Ntlm);
        assert_eq!(v, Some(b"foo".to_vec()));
    }

    // ---------- NtlmClient ----------

    fn fixed_random() -> NtlmRandom {
        NtlmRandom {
            client_challenge: [0x22u8; 8],
            exported_session_key: [0x33u8; 16],
        }
    }

    #[test]
    fn negotiate_produces_ntlmssp_type1() {
        let mut client = NtlmClient::new(
            NtlmCredentials::new("alice", "hunter2", "WORKGROUP"),
            fixed_random(),
        );
        assert_eq!(client.state(), NtlmAuthState::Initial);
        let bytes = client.negotiate().unwrap();
        // "NTLMSSP\0"
        assert_eq!(&bytes[0..8], b"NTLMSSP\0");
        // MessageType = 1 (NEGOTIATE)
        assert_eq!(&bytes[8..12], &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(client.state(), NtlmAuthState::WaitChallenge);
    }

    #[test]
    fn negotiate_twice_fails() {
        let mut client = NtlmClient::new(
            NtlmCredentials::new("u", "p", "d"),
            fixed_random(),
        );
        client.negotiate().unwrap();
        assert!(matches!(
            client.negotiate(),
            Err(NtlmError::InvalidState(_))
        ));
    }

    #[test]
    fn authenticate_before_negotiate_fails() {
        let mut client = NtlmClient::new(
            NtlmCredentials::new("u", "p", "d"),
            fixed_random(),
        );
        assert!(matches!(
            client.authenticate(&[]),
            Err(NtlmError::InvalidState(_))
        ));
    }

    /// Build a minimal synthetic NTLM CHALLENGE message for testing
    /// the `authenticate` path end-to-end. This isn't a perfect server
    /// simulation — just enough to exercise target_info parsing,
    /// response computation, and MIC generation.
    fn synthetic_challenge() -> Vec<u8> {
        use justrdp_pdu::ntlm::messages::NtlmVersion;

        // Target info: single MsvAvNbDomainName AV_PAIR + EOL.
        let nb = to_utf16le("TEST");
        let mut target_info = Vec::new();
        // AvId = MsvAvNbDomainName (2), length = nb.len()
        target_info.extend_from_slice(&2u16.to_le_bytes());
        target_info.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        target_info.extend_from_slice(&nb);
        // MsvAvEOL
        target_info.extend_from_slice(&[0, 0, 0, 0]);

        let target_name = to_utf16le("TEST");

        // Fixed header for CHALLENGE_MESSAGE (MS-NLMP 2.2.1.2):
        //   Signature(8) MessageType(4) TargetNameFields(8) NegotiateFlags(4)
        //   ServerChallenge(8) Reserved(8) TargetInfoFields(8) Version(8) = 56
        let header_size = 56u32;
        let target_name_off = header_size;
        let target_info_off = target_name_off + target_name.len() as u32;

        let flags = NegotiateFlags::client_default();

        let mut buf = Vec::new();
        buf.extend_from_slice(b"NTLMSSP\0");
        buf.extend_from_slice(&2u32.to_le_bytes()); // NTLM_CHALLENGE
        // TargetNameFields
        buf.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
        buf.extend_from_slice(&target_name_off.to_le_bytes());
        // Flags
        buf.extend_from_slice(&flags.bits().to_le_bytes());
        // ServerChallenge
        buf.extend_from_slice(&[0xAAu8; 8]);
        // Reserved
        buf.extend_from_slice(&[0u8; 8]);
        // TargetInfoFields
        buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        buf.extend_from_slice(&target_info_off.to_le_bytes());
        // Version
        let _ = NtlmVersion::windows_10();
        buf.extend_from_slice(&[10, 0, 0x61, 0x58, 0, 0, 0, 15]); // windows_10() encoded
        // Payload: target_name, target_info
        buf.extend_from_slice(&target_name);
        buf.extend_from_slice(&target_info);
        buf
    }

    #[test]
    fn authenticate_produces_ntlmssp_type3() {
        let mut client = NtlmClient::new(
            NtlmCredentials::new("alice", "hunter2", ""),
            fixed_random(),
        );
        client.negotiate().unwrap();

        let challenge = synthetic_challenge();
        let bytes = client.authenticate(&challenge).unwrap();
        // "NTLMSSP\0"
        assert_eq!(&bytes[0..8], b"NTLMSSP\0");
        // MessageType = 3 (AUTHENTICATE)
        assert_eq!(&bytes[8..12], &[0x03, 0x00, 0x00, 0x00]);
        // MIC is non-zero (filled in after first encode)
        let mic_offset = 72;
        assert_ne!(&bytes[mic_offset..mic_offset + 16], &[0u8; 16]);
        assert_eq!(client.state(), NtlmAuthState::Done);
    }

    #[test]
    fn authenticate_uses_server_domain_when_client_domain_empty() {
        let mut client = NtlmClient::new(
            NtlmCredentials::new("alice", "hunter2", ""),
            fixed_random(),
        );
        client.negotiate().unwrap();
        let bytes = client.authenticate(&synthetic_challenge()).unwrap();

        // The AUTHENTICATE message places domain_name at payload
        // offsets determined by DomainNameFields (offset 28..32). We
        // just sanity-check that the domain_name payload is non-empty.
        let domain_len = u16::from_le_bytes([bytes[28], bytes[29]]) as usize;
        assert!(domain_len > 0, "expected non-empty effective domain");
    }

    #[test]
    fn authenticate_rejects_malformed_challenge() {
        let mut client = NtlmClient::new(
            NtlmCredentials::new("u", "p", "d"),
            fixed_random(),
        );
        client.negotiate().unwrap();
        assert!(matches!(
            client.authenticate(b"not an NTLM message"),
            Err(NtlmError::BadChallenge)
        ));
    }
}
