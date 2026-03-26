//! RSA PKCS#1 v1.5 signing and verification for PKINIT.
//!
//! Implements RSA signature operations needed for PKINIT (RFC 4556):
//! - Sign with SHA-256 (PKCS#1 v1.5 padding)
//! - Verify with SHA-256 (PKCS#1 v1.5 unpadding)

use alloc::vec;
use alloc::vec::Vec;

use crate::bignum::BigUint;
use crate::crypto::Sha256;

/// RSA public key.
#[derive(Clone, Debug)]
pub struct RsaPublicKey {
    /// Modulus n.
    pub n: BigUint,
    /// Public exponent e.
    pub e: BigUint,
}

/// RSA private key (simple form: n, d).
#[derive(Clone, Debug)]
pub struct RsaPrivateKey {
    /// Modulus n.
    pub n: BigUint,
    /// Private exponent d.
    pub d: BigUint,
    /// Public exponent e (for extracting public key).
    pub e: BigUint,
}

impl RsaPrivateKey {
    /// Extract the public key.
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }

    /// Key size in bytes (modulus size).
    pub fn key_size(&self) -> usize {
        (self.n.bit_len() + 7) / 8
    }
}

impl RsaPublicKey {
    /// Key size in bytes (modulus size).
    pub fn key_size(&self) -> usize {
        (self.n.bit_len() + 7) / 8
    }
}

/// DigestInfo for SHA-256 (DER-encoded AlgorithmIdentifier + digest).
///
/// ```text
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm AlgorithmIdentifier { OID sha256, NULL },
///     digest          OCTET STRING
/// }
/// ```
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, // SEQUENCE (49 bytes)
    0x30, 0x0d, // SEQUENCE (13 bytes) - AlgorithmIdentifier
    0x06, 0x09, // OID (9 bytes)
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // sha-256
    0x05, 0x00, // NULL
    0x04, 0x20, // OCTET STRING (32 bytes)
];

/// Sign data with RSA PKCS#1 v1.5 (SHA-256).
///
/// 1. Hash the data with SHA-256
/// 2. Build DigestInfo = DER(AlgorithmIdentifier(sha256) || Hash)
/// 3. Pad: 0x00 || 0x01 || PS(0xFF...) || 0x00 || DigestInfo
/// 4. Convert to integer and compute m^d mod n
pub fn rsa_sign_sha256(key: &RsaPrivateKey, data: &[u8]) -> Vec<u8> {
    let k = key.key_size();

    // Hash
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    // Build DigestInfo
    let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + 32);
    digest_info.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    digest_info.extend_from_slice(&hash);

    // PKCS#1 v1.5 padding
    let t_len = digest_info.len(); // 19 + 32 = 51
    let ps_len = k - t_len - 3; // padding string length

    let mut em = vec![0u8; k];
    em[0] = 0x00;
    em[1] = 0x01;
    for i in 0..ps_len {
        em[2 + i] = 0xFF;
    }
    em[2 + ps_len] = 0x00;
    em[3 + ps_len..].copy_from_slice(&digest_info);

    // RSA private key operation: signature = em^d mod n
    let m = BigUint::from_be_bytes(&em);
    let s = m.mod_exp(&key.d, &key.n);
    s.to_be_bytes_padded(k)
}

/// Verify an RSA PKCS#1 v1.5 (SHA-256) signature.
///
/// 1. Compute s^e mod n to recover the padded message
/// 2. Verify PKCS#1 v1.5 padding structure
/// 3. Extract and compare the hash
pub fn rsa_verify_sha256(key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool {
    let k = key.key_size();

    if signature.len() != k {
        return false;
    }

    // RSA public key operation: em = signature^e mod n
    let s = BigUint::from_be_bytes(signature);
    let m = s.mod_exp(&key.e, &key.n);
    let em = m.to_be_bytes_padded(k);

    // Verify padding: 0x00 || 0x01 || PS || 0x00 || DigestInfo
    if em.len() < 11 || em[0] != 0x00 || em[1] != 0x01 {
        return false;
    }

    // Find end of PS (0xFF bytes)
    let mut i = 2;
    while i < em.len() && em[i] == 0xFF {
        i += 1;
    }

    if i < 10 || i >= em.len() || em[i] != 0x00 {
        return false;
    }

    i += 1; // skip 0x00 separator

    let digest_info = &em[i..];

    // Check DigestInfo prefix
    if digest_info.len() != SHA256_DIGEST_INFO_PREFIX.len() + 32 {
        return false;
    }

    if &digest_info[..SHA256_DIGEST_INFO_PREFIX.len()] != SHA256_DIGEST_INFO_PREFIX.as_slice() {
        return false;
    }

    let expected_hash = &digest_info[SHA256_DIGEST_INFO_PREFIX.len()..];

    // Hash the data
    let mut hasher = Sha256::new();
    hasher.update(data);
    let actual_hash = hasher.finalize();

    expected_hash == actual_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small RSA key for testing (NOT secure, just for unit tests).
    // p = 61, q = 53, n = 3233, e = 17, d = 2753
    // This is too small for PKCS#1 v1.5 with SHA-256 (needs at least 62 bytes),
    // so we use a precomputed 512-bit key for signature tests.

    // 512-bit RSA key (for testing only, NOT secure).
    // Generated values:
    // n = 0xB3510A2...
    // e = 65537
    // d = (computed)
    //
    // Instead of hardcoding a 512-bit key, let's test with the sign/verify
    // roundtrip using a known small key that's big enough for PKCS#1.
    //
    // For a 512-bit key, k=64, DigestInfo=51, PS_len=64-51-3=10 (minimum 8, OK).

    fn test_512bit_key() -> RsaPrivateKey {
        // This is a precomputed 512-bit RSA key for testing purposes ONLY.
        // n = p * q where:
        // p = 0xD4BCD52406F2C926 5A9EB1BFD1C29CD3 AB7ABBC8FF162323
        //     B82C8C55D59CC4CB
        // q = 0xD15ECE7A9AA437FA 7B9F99A5D3F7E553 DF87A0459929A6D1
        //     BD57A4D6F6CF0CD3
        //
        // For simplicity, let's use raw precomputed big-endian bytes.
        // Valid 512-bit RSA key (generated with Python, seed=42).
        let n_bytes = [
            0x9A, 0xD2, 0x93, 0x02, 0xA1, 0xC2, 0x45, 0x47,
            0x32, 0x6C, 0x6A, 0x4E, 0x0B, 0x25, 0xA5, 0x8B,
            0xFE, 0x2C, 0xA4, 0x03, 0xF3, 0x21, 0x59, 0x76,
            0x30, 0xBB, 0x58, 0xBD, 0xC3, 0x4D, 0xB1, 0xF0,
            0x86, 0xC1, 0x79, 0xCD, 0xF8, 0xCF, 0xB6, 0x36,
            0x79, 0x0D, 0xA2, 0x84, 0xB8, 0xE2, 0xE5, 0xB3,
            0xF0, 0x6B, 0xD4, 0x15, 0xEB, 0xCD, 0xAA, 0x2C,
            0xD7, 0xD6, 0x9A, 0x40, 0x67, 0x6A, 0xF1, 0xA7,
        ];

        let e_bytes = [0x01, 0x00, 0x01]; // 65537

        let d_bytes = [
            0x80, 0x03, 0xAF, 0x74, 0xD4, 0xA5, 0x9A, 0xBC,
            0xE4, 0xEF, 0x89, 0xF2, 0x9F, 0xFA, 0xEF, 0xE8,
            0x52, 0x31, 0x3D, 0x28, 0xDA, 0xE6, 0xEF, 0x5E,
            0xEF, 0xAA, 0x69, 0x14, 0xF7, 0x21, 0x0E, 0x08,
            0x25, 0x2F, 0xB2, 0x8D, 0x9A, 0x5B, 0x7E, 0xAA,
            0x12, 0xB4, 0x76, 0xB8, 0x68, 0x84, 0x0D, 0x78,
            0x30, 0x8A, 0x93, 0xCD, 0x69, 0x65, 0x8C, 0x63,
            0x67, 0x9A, 0x43, 0x36, 0xDD, 0xAB, 0x3F, 0x69,
        ];

        RsaPrivateKey {
            n: BigUint::from_be_bytes(&n_bytes),
            d: BigUint::from_be_bytes(&d_bytes),
            e: BigUint::from_be_bytes(&e_bytes),
        }
    }

    #[test]
    fn rsa_sign_verify_roundtrip() {
        let key = test_512bit_key();
        let data = b"Hello, PKINIT!";

        let signature = rsa_sign_sha256(&key, data);
        assert_eq!(signature.len(), 64); // 512-bit key = 64 bytes

        let public_key = key.public_key();
        assert!(rsa_verify_sha256(&public_key, data, &signature));
    }

    #[test]
    fn rsa_verify_wrong_data_fails() {
        let key = test_512bit_key();
        let signature = rsa_sign_sha256(&key, b"correct data");

        let public_key = key.public_key();
        assert!(!rsa_verify_sha256(&public_key, b"wrong data", &signature));
    }

    #[test]
    fn rsa_verify_wrong_signature_fails() {
        let key = test_512bit_key();
        let public_key = key.public_key();

        let bad_sig = vec![0x42u8; 64];
        assert!(!rsa_verify_sha256(&public_key, b"data", &bad_sig));
    }

    #[test]
    fn rsa_key_size() {
        let key = test_512bit_key();
        assert_eq!(key.key_size(), 64);
        assert_eq!(key.public_key().key_size(), 64);
    }
}
