#![forbid(unsafe_code)]

//! **Pluggable Authentication and Authorization (PAA) cookies**
//! (MS-TSGU §2.2.10).
//!
//! A PAA cookie is the authentication token that the gateway
//! evaluates inside `TsProxyAuthorizeTunnel` — separate from any
//! HTTP-level NTLM/Kerberos negotiation used to reach the
//! `rpcproxy.dll` endpoint. Two concrete forms exist in the spec:
//!
//! - **`CookieAuthData`** (§2.2.10.1) — a CredSSP-wrapped SPNEGO
//!   or NTLM token, conveyed as an opaque byte array.
//! - **Smart card cookie** (§2.2.10.2) — out of scope for this
//!   crate; requires PKINIT + a smart-card middleware integration.
//!
//! This module models the **wire container** only. Constructing the
//! inner bytes is the caller's responsibility (typically they hand
//! over a CredSSP output blob produced by `justrdp-connector`).

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// The PAA cookie shape actually placed inside the `cookie` field
/// of [`TsgPacketAuth`][crate::rpch::types::TsgPacketAuth].
///
/// On the wire this is simply the raw `cookieData` bytes — MS-TSGU
/// does not prepend a length or type tag (the outer NDR
/// `[size_is(cookieLen)]` array already carries the length).
/// Represented as a newtype mostly so that code that hands the
/// bytes around picks up type-level hints about what the blob
/// actually is.
///
/// The inner bytes carry NTLM-derived or CredSSP-wrapped credential
/// material, so `Debug` is masked and `Drop` zeroes the backing
/// capacity before the allocator reclaims it.
#[derive(Clone, PartialEq, Eq)]
pub struct PaaCookie {
    /// Opaque authentication material — typically a CredSSP
    /// `TSRequest` output blob that wraps an SPNEGO/NTLM token.
    /// Kept private so that the crate can later swap in a different
    /// internal representation (e.g. a borrowed slice) without
    /// breaking callers.
    bytes: Vec<u8>,
}

impl fmt::Debug for PaaCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaaCookie")
            .field("bytes", &format_args!("<{} bytes redacted>", self.bytes.len()))
            .finish()
    }
}

impl Drop for PaaCookie {
    fn drop(&mut self) {
        let cap = self.bytes.capacity();
        self.bytes.resize(cap, 0);
        self.bytes.fill(0);
        core::hint::black_box(&self.bytes);
        self.bytes.clear();
    }
}

impl PaaCookie {
    /// Wrap an opaque blob.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume and return the raw bytes.
    ///
    /// `Drop`'s zeroization is skipped for the returned `Vec` — the
    /// caller takes ownership of the sensitive buffer. `Drop` still
    /// runs on the (now-empty) wrapper to make the transfer explicit.
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }

    /// Length of the cookie in bytes — equals the `cookieLen` DWORD
    /// the server sees in the outer `TsgPacketAuth`.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl From<Vec<u8>> for PaaCookie {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

// =============================================================================
// Higher-level constructors
// =============================================================================

/// Maximum CredSSP version that the cookies we produce advertise.
/// Matches `justrdp-connector::credssp::TS_REQUEST_MAX_VERSION`. The
/// gateway verifies the cookie statically; any version ≥ 2 is
/// usually accepted.
pub const CREDSSP_COOKIE_VERSION: u32 = 6;

impl PaaCookie {
    /// Wrap a raw NTLM AUTHENTICATE message (Type 3 NTLMSSP blob)
    /// as a **bare** PAA cookie — no outer framing. This matches
    /// the wire shape that older Windows Server 2008 R2 gateways
    /// accept when configured with "RDG NTLM Authentication" RAP
    /// policy.
    ///
    /// The `authenticate_bytes` typically come from the third leg
    /// of the HTTP-level NTLM 401 exchange that this crate's
    /// [`authenticate_http_channel`][crate::auth] has already run —
    /// it is safe to reuse the same blob here because PAA cookies
    /// are verified against the user identity, not the transport
    /// context.
    pub fn from_ntlm_authenticate(authenticate_bytes: Vec<u8>) -> Self {
        Self::new(authenticate_bytes)
    }

    /// Wrap an NTLM AUTHENTICATE message as a CredSSP-formatted
    /// PAA cookie: the bytes are placed inside a minimal
    /// `TSRequest { version, negoTokens: [negoToken] }` DER
    /// structure as required by MS-TSGU §2.2.10.1 when the gateway
    /// is configured for CredSSP-based PAA (the default for
    /// Windows Server 2012+ RD Gateways).
    ///
    /// The returned cookie is the canonical format that
    /// `rpcproxy.dll` verifies.
    pub fn from_ntlm_authenticate_as_credssp(authenticate_bytes: &[u8]) -> Self {
        Self::new(encode_ts_request_nego_tokens(
            authenticate_bytes,
            CREDSSP_COOKIE_VERSION,
        ))
    }

    /// Wrap a caller-supplied already-encoded TSRequest DER blob
    /// (produced by driving `justrdp-connector::CredsspSequence`
    /// to completion or by a peer library) as a PAA cookie. Use
    /// this when your gateway requires a full CredSSP exchange
    /// beyond what [`Self::from_ntlm_authenticate_as_credssp`]
    /// covers (Kerberos / SPNEGO / delegated credentials).
    pub fn from_credssp_ts_request(ts_request_der: Vec<u8>) -> Self {
        Self::new(ts_request_der)
    }
}

// =============================================================================
// Minimal TSRequest DER encoder
// =============================================================================
// Grammar per MS-CSSP §2.2.1:
//
//   TSRequest ::= SEQUENCE {
//       version     [0] INTEGER,
//       negoTokens  [1] NegoData OPTIONAL,
//       ...
//   }
//   NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
//
// We emit `version` + one-item `negoTokens` and nothing else —
// that is the exact shape Microsoft's rpcproxy.dll accepts as a
// PAA cookie. Reimplements the minimum slice of ASN.1 DER needed
// so that `justrdp-gateway` does not have to pull in
// `justrdp-connector` for a single struct.

fn encode_ts_request_nego_tokens(nego_token: &[u8], version: u32) -> Vec<u8> {
    let mut inner = Vec::new();
    // [0] version INTEGER
    let v = der_encode_integer(version);
    inner.extend(der_encode_context_tag(0, &v));
    // [1] negoTokens SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
    let octet = der_encode_octet_string(nego_token);
    let inner_seq = der_encode_sequence(&der_encode_context_tag(0, &octet));
    let outer_seq = der_encode_sequence(&inner_seq);
    inner.extend(der_encode_context_tag(1, &outer_seq));
    // Outer SEQUENCE wrapping the whole thing.
    der_encode_sequence(&inner)
}

fn der_encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        Vec::from([len as u8])
    } else if len < 256 {
        Vec::from([0x81, len as u8])
    } else if len < 65536 {
        Vec::from([0x82, (len >> 8) as u8, (len & 0xFF) as u8])
    } else {
        Vec::from([
            0x83,
            (len >> 16) as u8,
            (len >> 8) as u8,
            (len & 0xFF) as u8,
        ])
    }
}

fn der_encode_tag_and_value(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    out.push(tag);
    out.extend(der_encode_length(value.len()));
    out.extend_from_slice(value);
    out
}

fn der_encode_sequence(value: &[u8]) -> Vec<u8> {
    der_encode_tag_and_value(0x30, value)
}

fn der_encode_context_tag(tag_num: u8, value: &[u8]) -> Vec<u8> {
    der_encode_tag_and_value(0xA0 | tag_num, value)
}

fn der_encode_octet_string(value: &[u8]) -> Vec<u8> {
    der_encode_tag_and_value(0x04, value)
}

fn der_encode_integer(value: u32) -> Vec<u8> {
    // Strip leading zero bytes; keep at least one byte; add a
    // leading zero if the MSB is set (unsigned → positive INTEGER).
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 3 && bytes[start] == 0 {
        start += 1;
    }
    let mut tail = alloc::vec::Vec::from(&bytes[start..]);
    if tail[0] & 0x80 != 0 {
        tail.insert(0, 0);
    }
    der_encode_tag_and_value(0x02, &tail)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paa_cookie_wraps_arbitrary_bytes() {
        let c = PaaCookie::new(alloc::vec![0xAAu8, 0xBB, 0xCC]);
        assert_eq!(c.len(), 3);
        assert!(!c.is_empty());
        assert_eq!(c.as_bytes(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn paa_cookie_empty_is_empty() {
        let c = PaaCookie::new(Vec::<u8>::new());
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn paa_cookie_round_trips_through_into_from_vec() {
        let bytes = alloc::vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let c: PaaCookie = bytes.clone().into();
        assert_eq!(c.into_bytes(), bytes);
    }

    #[test]
    fn from_ntlm_authenticate_is_passthrough() {
        let ntlm_auth = alloc::vec![0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x03];
        let c = PaaCookie::from_ntlm_authenticate(ntlm_auth.clone());
        assert_eq!(c.as_bytes(), &ntlm_auth[..]);
    }

    #[test]
    fn from_ntlm_authenticate_as_credssp_wraps_in_ts_request() {
        // Short synthetic "AUTHENTICATE" blob.
        let ntlm = alloc::vec![0x41u8; 16];
        let cookie = PaaCookie::from_ntlm_authenticate_as_credssp(&ntlm);
        let bytes = cookie.as_bytes();

        // Outer should be a DER SEQUENCE: tag 0x30.
        assert_eq!(bytes[0], 0x30, "outer DER tag must be SEQUENCE");

        // The encoded blob must be longer than the raw NTLM input
        // (because we wrap it in the TSRequest frame).
        assert!(bytes.len() > ntlm.len() + 10);

        // Find the octet-string tag (0x04) followed by our length
        // byte and the payload. The byte just before the payload
        // should encode the NTLM length (16).
        let mut i = 0;
        let mut found = false;
        while i + 1 < bytes.len() {
            if bytes[i] == 0x04 && bytes[i + 1] as usize == ntlm.len() {
                let start = i + 2;
                if bytes[start..start + ntlm.len()] == ntlm[..] {
                    found = true;
                    break;
                }
            }
            i += 1;
        }
        assert!(found, "NTLM authenticate bytes must appear inside an OCTET STRING");
    }

    #[test]
    fn from_ntlm_authenticate_as_credssp_handles_long_blobs() {
        // NTLM AUTHENTICATE can reach several hundred bytes;
        // exercise the multi-byte length path.
        let ntlm = alloc::vec![0xAAu8; 300];
        let cookie = PaaCookie::from_ntlm_authenticate_as_credssp(&ntlm);
        let bytes = cookie.as_bytes();
        assert_eq!(bytes[0], 0x30);
        // Length prefix must be > 1 byte for a blob over 127.
        assert_eq!(bytes[1] & 0x80, 0x80, "long-form DER length");
        // Still roundtrips the payload somewhere in the body.
        assert!(bytes.windows(ntlm.len()).any(|w| w == ntlm));
    }

    #[test]
    fn from_credssp_ts_request_is_passthrough() {
        let blob = alloc::vec![0x30u8, 0x02, 0x01, 0x01];
        let c = PaaCookie::from_credssp_ts_request(blob.clone());
        assert_eq!(c.as_bytes(), &blob[..]);
    }

    #[test]
    fn der_encode_integer_strips_leading_zeros() {
        assert_eq!(der_encode_integer(6), alloc::vec![0x02, 0x01, 0x06]);
    }

    #[test]
    fn der_encode_integer_preserves_sign_bit_with_leading_zero() {
        // `0x80` has the MSB set → must prefix a leading zero to
        // encode as a positive integer.
        assert_eq!(
            der_encode_integer(0x80),
            alloc::vec![0x02, 0x02, 0x00, 0x80]
        );
    }

    #[test]
    fn der_encode_length_short_and_long_forms() {
        assert_eq!(der_encode_length(0), alloc::vec![0]);
        assert_eq!(der_encode_length(127), alloc::vec![127]);
        assert_eq!(der_encode_length(128), alloc::vec![0x81, 128]);
        assert_eq!(der_encode_length(300), alloc::vec![0x82, 0x01, 0x2C]);
    }

    /// Cross-validation: our inlined minimal TSRequest encoder must
    /// produce byte-identical output to `justrdp-connector`'s
    /// canonical one for the subset of fields we use.
    #[test]
    fn output_matches_justrdp_connector_ts_request_encoder() {
        use justrdp_connector::credssp::ts_request::TsRequest;

        let ntlm = alloc::vec![0x4Eu8, 0x54, 0x4C, 0x4D]; // "NTLM" marker
        let ours = PaaCookie::from_ntlm_authenticate_as_credssp(&ntlm)
            .into_bytes();

        let mut canonical = TsRequest::new();
        canonical.version = CREDSSP_COOKIE_VERSION;
        canonical.nego_tokens = Some(ntlm.clone());
        let theirs = canonical.encode();

        assert_eq!(
            ours, theirs,
            "inlined PAA cookie encoder diverges from justrdp-connector canonical"
        );
    }

    /// Same cross-validation for the long-length path.
    #[test]
    fn output_matches_justrdp_connector_for_long_nego_tokens() {
        use justrdp_connector::credssp::ts_request::TsRequest;

        let ntlm = alloc::vec![0x55u8; 400];
        let ours = PaaCookie::from_ntlm_authenticate_as_credssp(&ntlm)
            .into_bytes();

        let mut canonical = TsRequest::new();
        canonical.version = CREDSSP_COOKIE_VERSION;
        canonical.nego_tokens = Some(ntlm.clone());
        let theirs = canonical.encode();

        assert_eq!(ours, theirs);
    }
}
