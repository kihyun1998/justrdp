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

/// The PAA cookie shape actually placed inside the `cookie` field
/// of [`TsgPacketAuth`][crate::rpch::types::TsgPacketAuth].
///
/// On the wire this is simply the raw `cookieData` bytes — MS-TSGU
/// does not prepend a length or type tag (the outer NDR
/// `[size_is(cookieLen)]` array already carries the length).
/// Represented as a newtype mostly so that code that hands the
/// bytes around picks up type-level hints about what the blob
/// actually is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaaCookie {
    /// Opaque authentication material — typically a CredSSP
    /// `TSRequest` output blob that wraps an SPNEGO/NTLM token.
    /// Kept private so that the crate can later swap in a different
    /// internal representation (e.g. a borrowed slice) without
    /// breaking callers.
    bytes: Vec<u8>,
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
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
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
}
