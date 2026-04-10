#![forbid(unsafe_code)]

//! Public [`ServerCertVerifier`] trait and default implementations.
//!
//! This is the user-facing verification hook. Backends (rustls, native-tls)
//! wrap their own internal verifiers around an instance of this trait so
//! callers can make accept/reject decisions without touching backend types.

use std::fmt;

use crate::extract_spki_from_cert_der;

/// Decision returned by [`ServerCertVerifier::verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertDecision {
    /// Trust this certificate permanently (TLS handshake proceeds).
    Accept,
    /// Reject this certificate (TLS handshake fails).
    Reject,
    /// Trust this certificate only for the current session.
    ///
    /// The TLS handshake proceeds identically to `Accept`; the distinction is
    /// a **semantic marker only** — this crate does not track sessions or enforce
    /// the "once" constraint. It is the caller's responsibility not to persist
    /// an `AcceptOnce` result across sessions.
    AcceptOnce,
}

impl CertDecision {
    /// Returns `true` if the decision allows the handshake to proceed.
    pub fn is_accepted(self) -> bool {
        matches!(self, Self::Accept | Self::AcceptOnce)
    }
}

/// Application hook for deciding whether to trust a server certificate.
///
/// Implementations see the leaf certificate in DER form (X.509) and the
/// server name the client is connecting to. A typical GUI client would
/// pop a dialog asking the user to accept unknown certificates; a headless
/// service would compare against a pinned fingerprint.
pub trait ServerCertVerifier: Send + Sync {
    /// Inspect the certificate and return a trust decision.
    ///
    /// `cert_der` is the leaf certificate (first in the chain) as raw DER.
    /// `server_name` is the SNI hostname the client requested.
    fn verify(&self, cert_der: &[u8], server_name: &str) -> CertDecision;
}

/// Verifier that unconditionally accepts every certificate.
///
/// Equivalent to `mstsc.exe` default behavior — encryption still protects
/// the channel, but server identity is not verified. Appropriate for RDP
/// servers with self-signed certificates on trusted networks.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAll;

impl ServerCertVerifier for AcceptAll {
    fn verify(&self, _cert_der: &[u8], _server_name: &str) -> CertDecision {
        CertDecision::Accept
    }
}

/// Verifier that accepts a certificate only if its SubjectPublicKeyInfo
/// matches a pre-configured SHA-256 fingerprint.
///
/// Uses SPKI pinning (not full-cert pinning) so that certificate re-issuance
/// with the same key pair does not break the pin.
#[derive(Clone)]
pub struct PinnedSpki {
    expected_sha256: [u8; 32],
}

impl PinnedSpki {
    /// Create a new pinned verifier from a pre-computed SHA-256 digest of
    /// the DER-encoded SubjectPublicKeyInfo.
    pub fn new(spki_sha256: [u8; 32]) -> Self {
        Self {
            expected_sha256: spki_sha256,
        }
    }

    /// Convenience constructor: compute the SPKI digest from a certificate DER.
    ///
    /// Useful during first-run enrollment where the user has just accepted
    /// a self-signed certificate and you want to pin it for future sessions.
    pub fn from_cert_der(cert_der: &[u8]) -> Option<Self> {
        let spki = extract_spki_from_cert_der(cert_der)?;
        Some(Self::new(justrdp_core::crypto::sha256(&spki)))
    }

    /// Returns the expected SPKI fingerprint.
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.expected_sha256
    }
}

impl fmt::Debug for PinnedSpki {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only show first 4 bytes of fingerprint in Debug output to avoid
        // cluttering logs without completely hiding identity.
        write!(
            f,
            "PinnedSpki {{ sha256: {:02x}{:02x}{:02x}{:02x}... }}",
            self.expected_sha256[0],
            self.expected_sha256[1],
            self.expected_sha256[2],
            self.expected_sha256[3],
        )
    }
}

impl ServerCertVerifier for PinnedSpki {
    fn verify(&self, cert_der: &[u8], _server_name: &str) -> CertDecision {
        let Some(spki) = extract_spki_from_cert_der(cert_der) else {
            return CertDecision::Reject;
        };
        let actual = justrdp_core::crypto::sha256(&spki);
        if constant_time_eq(&actual, &self.expected_sha256) {
            CertDecision::Accept
        } else {
            CertDecision::Reject
        }
    }
}

/// Constant-time comparison for 32-byte fingerprints.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_all_always_accepts() {
        let v = AcceptAll;
        assert_eq!(v.verify(b"anything", "srv"), CertDecision::Accept);
        assert_eq!(v.verify(&[], ""), CertDecision::Accept);
    }

    #[test]
    fn cert_decision_is_accepted() {
        assert!(CertDecision::Accept.is_accepted());
        assert!(CertDecision::AcceptOnce.is_accepted());
        assert!(!CertDecision::Reject.is_accepted());
    }

    #[test]
    fn pinned_spki_rejects_unparseable_cert() {
        let pin = PinnedSpki::new([0u8; 32]);
        assert_eq!(pin.verify(&[0xFF, 0xFF, 0xFF], "srv"), CertDecision::Reject);
    }

    #[test]
    fn pinned_spki_rejects_wrong_fingerprint() {
        // Build a minimal valid cert so extraction succeeds, then pin to
        // a different fingerprint.
        let cert = build_minimal_cert();
        let pin = PinnedSpki::new([0xAA; 32]);
        assert_eq!(pin.verify(&cert, "srv"), CertDecision::Reject);
    }

    #[test]
    fn pinned_spki_accepts_matching_fingerprint() {
        let cert = build_minimal_cert();
        let pin = PinnedSpki::from_cert_der(&cert).expect("valid cert");
        assert_eq!(pin.verify(&cert, "srv"), CertDecision::Accept);
    }

    #[test]
    fn constant_time_eq_rejects_differences() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        assert!(constant_time_eq(&a, &b));
        b[31] = 1;
        assert!(!constant_time_eq(&a, &b));
        b[31] = 0;
        b[0] = 1;
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn pinned_spki_debug_redacts_tail() {
        let pin = PinnedSpki::new([
            0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
        ]);
        let s = format!("{pin:?}");
        assert!(s.contains("deadbeef"));
        assert!(!s.contains("0102030405")); // tail should be hidden
    }

    /// Build a minimal valid X.509 cert DER with a parseable SPKI.
    /// Mirrors the helper in `lib.rs` tests.
    fn build_minimal_cert() -> Vec<u8> {
        fn der_len(len: usize) -> Vec<u8> {
            if len < 0x80 {
                vec![len as u8]
            } else if len < 0x100 {
                vec![0x81, len as u8]
            } else {
                vec![0x82, (len >> 8) as u8, len as u8]
            }
        }
        fn seq(content: &[u8]) -> Vec<u8> {
            let mut r = vec![0x30];
            r.extend(der_len(content.len()));
            r.extend_from_slice(content);
            r
        }

        // SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        let algo = vec![0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00];
        let bitstr = vec![0x03, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04];
        let mut spki_body = Vec::new();
        spki_body.extend_from_slice(&algo);
        spki_body.extend_from_slice(&bitstr);
        let spki = seq(&spki_body);

        let version = vec![0xA0, 0x03, 0x02, 0x01, 0x02];
        let serial = vec![0x02, 0x01, 0x01];
        let sig_algo = vec![0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03];
        let issuer = vec![0x30, 0x00];
        let validity = vec![0x30, 0x00];
        let subject = vec![0x30, 0x00];

        let mut tbs_body = Vec::new();
        tbs_body.extend_from_slice(&version);
        tbs_body.extend_from_slice(&serial);
        tbs_body.extend_from_slice(&sig_algo);
        tbs_body.extend_from_slice(&issuer);
        tbs_body.extend_from_slice(&validity);
        tbs_body.extend_from_slice(&subject);
        tbs_body.extend_from_slice(&spki);
        let tbs = seq(&tbs_body);

        let outer_sig_algo = vec![0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03];
        let sig_value = vec![0x03, 0x03, 0x00, 0xAA, 0xBB];

        let mut cert_body = Vec::new();
        cert_body.extend_from_slice(&tbs);
        cert_body.extend_from_slice(&outer_sig_algo);
        cert_body.extend_from_slice(&sig_value);
        seq(&cert_body)
    }
}
