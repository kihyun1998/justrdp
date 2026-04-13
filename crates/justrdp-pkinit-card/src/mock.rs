#![forbid(unsafe_code)]

//! `MockSmartcardProvider` — in-memory test fixture, no hardware needed.
//!
//! Returns a fixed minimal X.509 certificate and signs digests with a
//! fixed 512-bit RSA test key (the same key used by `justrdp-core`'s
//! RSA unit tests). Suitable for unit and integration tests that
//! exercise the PKINIT smartcard code path end-to-end.
//!
//! **Do not use in production.** The private key is hard-coded and
//! publicly visible in the source tree.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use justrdp_core::bignum::BigUint;
use justrdp_core::rsa::{rsa_sign_sha256_digest, RsaPrivateKey};
use justrdp_pdu::kerberos::asn1::{build_context_tag, build_sequence, OID_SHA256_WITH_RSA};

use crate::provider::{SmartcardError, SmartcardProvider};

/// Hard-coded 512-bit RSA test key (modulus `n`, private exponent `d`).
/// Same vectors used by `justrdp-core`'s RSA tests so the mock stays
/// deterministic and easy to cross-validate.
const TEST_KEY_N: [u8; 64] = [
    0x9A, 0xD2, 0x93, 0x02, 0xA1, 0xC2, 0x45, 0x47, 0x32, 0x6C, 0x6A, 0x4E, 0x0B, 0x25, 0xA5, 0x8B,
    0xFE, 0x2C, 0xA4, 0x03, 0xF3, 0x21, 0x59, 0x76, 0x30, 0xBB, 0x58, 0xBD, 0xC3, 0x4D, 0xB1, 0xF0,
    0x86, 0xC1, 0x79, 0xCD, 0xF8, 0xCF, 0xB6, 0x36, 0x79, 0x0D, 0xA2, 0x84, 0xB8, 0xE2, 0xE5, 0xB3,
    0xF0, 0x6B, 0xD4, 0x15, 0xEB, 0xCD, 0xAA, 0x2C, 0xD7, 0xD6, 0x9A, 0x40, 0x67, 0x6A, 0xF1, 0xA7,
];
const TEST_KEY_D: [u8; 64] = [
    0x80, 0x03, 0xAF, 0x74, 0xD4, 0xA5, 0x9A, 0xBC, 0xE4, 0xEF, 0x89, 0xF2, 0x9F, 0xFA, 0xEF, 0xE8,
    0x52, 0x31, 0x3D, 0x28, 0xDA, 0xE6, 0xEF, 0x5E, 0xEF, 0xAA, 0x69, 0x14, 0xF7, 0x21, 0x0E, 0x08,
    0x25, 0x2F, 0xB2, 0x8D, 0x9A, 0x5B, 0x7E, 0xAA, 0x12, 0xB4, 0x76, 0xB8, 0x68, 0x84, 0x0D, 0x78,
    0x30, 0x8A, 0x93, 0xCD, 0x69, 0x65, 0x8C, 0x63, 0x67, 0x9A, 0x43, 0x36, 0xDD, 0xAB, 0x3F, 0x69,
];

fn build_mock_certificate() -> Vec<u8> {
    // Minimal parseable Certificate ::= SEQUENCE { TBSCertificate, ... }
    // TBSCertificate omits most fields except the ones
    // `cms::extract_cert_issuer_serial` needs (version, serialNumber,
    // signature alg, issuer). This is the same shape used by the
    // existing `pkinit_build_as_req_produces_output` test in
    // `kerberos.rs`, so we know it's parseable.
    let tbs = build_sequence(|w| {
        // [0] version = v3(2)
        let v = build_context_tag(0, |w| w.write_integer(2));
        w.write_raw(&v);
        // serialNumber
        w.write_integer(1);
        // signature AlgorithmIdentifier
        let algo = build_sequence(|w| {
            w.write_oid(OID_SHA256_WITH_RSA);
            w.write_null();
        });
        w.write_raw(&algo);
        // issuer (empty Name)
        let issuer = build_sequence(|_w| {});
        w.write_raw(&issuer);
    });
    build_sequence(|w| {
        w.write_raw(&tbs);
    })
}

/// In-memory smartcard provider for tests and examples.
pub struct MockSmartcardProvider {
    certificate: Vec<u8>,
    intermediates: Vec<Vec<u8>>,
    key: RsaPrivateKey,
    /// PIN that `verify_pin` will accept. `None` means any PIN passes.
    expected_pin: Option<Vec<u8>>,
    /// Set to `true` after a successful `verify_pin` (mock-internal,
    /// not enforced by `sign_digest` — PKINIT layer assumes the
    /// application has already verified).
    pin_verified: bool,
}

impl MockSmartcardProvider {
    /// Create a mock provider with the embedded fixture certificate
    /// and key. PIN verification accepts any input.
    pub fn new() -> Self {
        Self {
            certificate: build_mock_certificate(),
            intermediates: Vec::new(),
            key: RsaPrivateKey {
                n: BigUint::from_be_bytes(&TEST_KEY_N),
                d: BigUint::from_be_bytes(&TEST_KEY_D),
                e: BigUint::from_be_bytes(&[0x01, 0x00, 0x01]),
            },
            expected_pin: None,
            pin_verified: false,
        }
    }

    /// Configure the provider to require a specific PIN. Pass an empty
    /// slice to require an empty PIN (rather than `None` which accepts
    /// any).
    pub fn with_required_pin(mut self, pin: &[u8]) -> Self {
        self.expected_pin = Some(pin.to_vec());
        self
    }

    /// Inject an intermediate CA certificate into the returned chain
    /// (root excluded). Useful for testing chain handling.
    pub fn with_intermediate(mut self, der: Vec<u8>) -> Self {
        self.intermediates.push(der);
        self
    }

    /// Whether `verify_pin` has been called successfully on this
    /// provider. Test-only inspection helper — gated behind
    /// `#[cfg(test)]` so the public API stays minimal.
    #[cfg(test)]
    pub(crate) fn is_pin_verified(&self) -> bool {
        self.pin_verified
    }
}

impl Default for MockSmartcardProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SmartcardProvider for MockSmartcardProvider {
    fn get_certificate(&self) -> Vec<u8> {
        self.certificate.clone()
    }

    fn get_intermediate_chain(&self) -> Vec<Vec<u8>> {
        self.intermediates.clone()
    }

    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), SmartcardError> {
        match &self.expected_pin {
            Some(expected) if !ct_eq(expected.as_slice(), pin) => {
                Err(SmartcardError::PinIncorrect { remaining_tries: Some(2) })
            }
            _ => {
                self.pin_verified = true;
                Ok(())
            }
        }
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, SmartcardError> {
        if digest.len() != 32 {
            return Err(SmartcardError::CryptoFailure(
                "digest must be 32 bytes (SHA-256)".to_string(),
            ));
        }
        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(digest);
        rsa_sign_sha256_digest(&self.key, &digest_arr)
            .map_err(|e| SmartcardError::CryptoFailure(format_crypto_error(e)))
    }
}

fn format_crypto_error(e: justrdp_core::CryptoError) -> String {
    // TODO: switch to `{e}` once justrdp-core::CryptoError implements Display.
    let mut s = String::new();
    use core::fmt::Write;
    let _ = write!(s, "{e:?}");
    s
}

/// Constant-time byte-slice equality. Returns `true` iff `a` and `b`
/// have the same length and every byte matches. The branch on `len`
/// itself is not constant-time across different-length inputs, but
/// equal-length comparisons run in time independent of the contents.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

impl Drop for MockSmartcardProvider {
    fn drop(&mut self) {
        if let Some(ref mut p) = self.expected_pin {
            p.fill(0);
        }
        // RsaPrivateKey has its own Drop that zeroes n/d/e.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use justrdp_pdu::cms::extract_cert_issuer_serial;

    #[test]
    fn mock_certificate_is_parseable() {
        // The PKINIT layer calls extract_cert_issuer_serial — the mock
        // cert must round-trip through it.
        let p = MockSmartcardProvider::new();
        let cert = p.get_certificate();
        let (issuer, serial) = extract_cert_issuer_serial(&cert).unwrap();
        assert!(!issuer.is_empty());
        assert!(!serial.is_empty());
    }

    #[test]
    fn mock_intermediate_chain_starts_empty() {
        let p = MockSmartcardProvider::new();
        assert!(p.get_intermediate_chain().is_empty());
    }

    #[test]
    fn mock_intermediate_chain_with_extra() {
        let p = MockSmartcardProvider::new()
            .with_intermediate(vec![0x30, 0x00])
            .with_intermediate(vec![0x30, 0x01]);
        assert_eq!(p.get_intermediate_chain().len(), 2);
    }

    #[test]
    fn mock_verify_pin_accepts_any_when_unset() {
        let mut p = MockSmartcardProvider::new();
        assert!(p.verify_pin(b"123456").is_ok());
        assert!(p.is_pin_verified());
    }

    #[test]
    fn mock_verify_pin_enforces_when_required() {
        let mut p = MockSmartcardProvider::new().with_required_pin(b"1234");
        assert!(matches!(
            p.verify_pin(b"wrong"),
            Err(SmartcardError::PinIncorrect { .. })
        ));
        assert!(!p.is_pin_verified());
        assert!(p.verify_pin(b"1234").is_ok());
        assert!(p.is_pin_verified());
    }

    #[test]
    fn mock_sign_digest_round_trip() {
        let p = MockSmartcardProvider::new();
        let digest = [0x42u8; 32];
        let sig = p.sign_digest(&digest).unwrap();
        // 512-bit modulus → 64-byte signature
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn mock_sign_digest_rejects_wrong_length() {
        let p = MockSmartcardProvider::new();
        assert!(matches!(
            p.sign_digest(&[0u8; 31]),
            Err(SmartcardError::CryptoFailure(_))
        ));
        assert!(matches!(
            p.sign_digest(&[0u8; 33]),
            Err(SmartcardError::CryptoFailure(_))
        ));
    }

    #[test]
    fn mock_sign_digest_deterministic() {
        // PKCS#1 v1.5 is deterministic; same input → same output.
        let p = MockSmartcardProvider::new();
        let d = [0x55u8; 32];
        assert_eq!(p.sign_digest(&d).unwrap(), p.sign_digest(&d).unwrap());
    }
}
