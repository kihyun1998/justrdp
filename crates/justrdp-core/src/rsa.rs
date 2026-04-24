#![forbid(unsafe_code)]

//! RSA PKCS#1 v1.5 signing and verification for PKINIT.
//!
//! Implements RSA signature operations needed for PKINIT (RFC 4556):
//! - Sign with SHA-256 (PKCS#1 v1.5 padding)
//! - Verify with SHA-256 (PKCS#1 v1.5 unpadding)

use alloc::vec;
use alloc::vec::Vec;

use crate::bignum::BigUint;
use crate::crypto::Sha256;
use crate::error::{CryptoError, CryptoResult};

/// RSA public key.
#[derive(Clone, Debug)]
pub struct RsaPublicKey {
    /// Modulus n.
    pub n: BigUint,
    /// Public exponent e.
    pub e: BigUint,
}

/// RSA private key (simple form: n, d).
///
/// Implements `Drop` to zeroize the private exponent `d` on destruction.
#[derive(Clone)]
pub struct RsaPrivateKey {
    /// Modulus n.
    pub n: BigUint,
    /// Private exponent d.
    pub d: BigUint,
    /// Public exponent e (for extracting public key).
    pub e: BigUint,
}

impl core::fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("n", &self.n)
            .field("d", &"[REDACTED]")
            .field("e", &self.e)
            .finish()
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.d.zeroize();
        self.n.zeroize();
    }
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
/// PKCS#1 v1.5 minimum overhead: 0x00 || 0x01 || PS (>=8 bytes) || 0x00 = 11 bytes.
/// RFC 8017 §9.2.
const PKCS1_V15_OVERHEAD: usize = 11;

const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, // SEQUENCE (49 bytes)
    0x30, 0x0d, // SEQUENCE (13 bytes) - AlgorithmIdentifier
    0x06, 0x09, // OID (9 bytes)
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // sha-256
    0x05, 0x00, // NULL
    0x04, 0x20, // OCTET STRING (32 bytes)
];

/// Build a PKCS#1 v1.5 encoded message for SHA-256 digests, exposed for
/// smartcard backends that perform raw RSA on the card and require the
/// host to do the padding (PIV NIST SP 800-73-4 §3.3.2).
///
/// `modulus_size_bytes` is the RSA modulus size in bytes (e.g. 256 for
/// RSA-2048). Returns `None` if the modulus is too small to fit the
/// PKCS#1 v1.5 envelope around a SHA-256 DigestInfo.
pub fn pkcs1_v15_pad_sha256_digest(
    modulus_size_bytes: usize,
    digest: &[u8; 32],
) -> Option<Vec<u8>> {
    build_pkcs1_em(modulus_size_bytes, digest)
}

/// Build PKCS#1 v1.5 encoded message: 0x00 || 0x01 || PS (0xFF...) || 0x00 || DigestInfo.
/// RFC 8017 §9.2 — returns None if key is too small.
fn build_pkcs1_em(k: usize, hash: &[u8; 32]) -> Option<Vec<u8>> {
    let t_len = SHA256_DIGEST_INFO_PREFIX.len() + 32;
    if k < t_len + PKCS1_V15_OVERHEAD {
        return None;
    }
    let ps_len = k - t_len - 3;

    let mut em = vec![0u8; k];
    em[0] = 0x00;
    em[1] = 0x01;
    em[2..2 + ps_len].fill(0xFF);
    em[2 + ps_len] = 0x00;
    em[3 + ps_len..3 + ps_len + SHA256_DIGEST_INFO_PREFIX.len()]
        .copy_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    em[3 + ps_len + SHA256_DIGEST_INFO_PREFIX.len()..].copy_from_slice(hash);
    Some(em)
}

/// Sign data with RSA PKCS#1 v1.5 (SHA-256).
///
/// 1. Hash the data with SHA-256
/// 2. Build DigestInfo = DER(AlgorithmIdentifier(sha256) || Hash)
/// 3. Pad: 0x00 || 0x01 || PS(0xFF...) || 0x00 || DigestInfo
/// 4. Convert to integer and compute m^d mod n
///
/// Returns `CryptoError::InvalidKeySize` if the key is too small for PKCS#1 v1.5
/// with SHA-256 (minimum 62 bytes / 496 bits).
pub fn rsa_sign_sha256(key: &RsaPrivateKey, data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    rsa_sign_sha256_digest(key, &hash)
}

/// Sign a pre-computed SHA-256 digest with RSA PKCS#1 v1.5.
///
/// This is the primitive used by the smartcard provider abstraction
/// (`SmartcardProvider::sign_digest` in `justrdp-pkinit-card`): the host
/// computes the digest, the card (or mock) applies PKCS#1 v1.5 padding +
/// RSA private-key exponentiation. Matches PIV (NIST SP 800-73-4 §3.3.2)
/// and PKCS#11 `CKM_RSA_PKCS` with pre-hashed input.
///
/// Returns `CryptoError::InvalidKeySize` if the key is too small.
pub fn rsa_sign_sha256_digest(key: &RsaPrivateKey, digest: &[u8; 32]) -> CryptoResult<Vec<u8>> {
    let k = key.key_size();
    let em = build_pkcs1_em(k, digest).ok_or(CryptoError::InvalidKeySize)?;
    // SECURITY: mod_exp's per-iteration body is branchless (Montgomery
    // ladder + ct_swap_limbs), but the iteration count derives from
    // `d.bit_len()`, which can leak the bit-length of the private
    // exponent to a local timing observer. For RSA keys generated by
    // standard tools `d` is always exactly `k*8` bits, so this leaks
    // nothing in practice — but keep this in mind when accepting
    // attacker-influenced keys.
    let m = BigUint::from_be_bytes(&em);
    let s = m.mod_exp(&key.d, &key.n);
    Ok(s.to_be_bytes_padded(k))
}

/// RSA raw public-key operation for RDP Standard Security.
///
/// RDP uses a non-standard RSA encryption scheme:
/// 1. Input is in little-endian byte order
/// 2. Zero-padded to modulus size
/// 3. Compute m^e mod n
/// 4. Output is in little-endian byte order
///
/// Reference: MS-RDPBCGR 5.3.4.1
pub fn rsa_public_encrypt_rdp(key: &RsaPublicKey, plaintext: &[u8]) -> Vec<u8> {
    let k = key.key_size();

    // RDP sends data in little-endian: convert LE input to BigUint
    let m = BigUint::from_le_bytes(plaintext);

    // RSA public key operation: c = m^e mod n
    let c = m.mod_exp(&key.e, &key.n);

    // Output in little-endian, padded to modulus size
    c.to_le_bytes_padded(k)
}

/// Server-side inverse of [`rsa_public_encrypt_rdp`] -- decrypt a
/// Security Exchange PDU's `encryptedClientRandom` using the server's
/// RSA private key.
///
/// 1. Input is in little-endian byte order (typically
///    `ciphertext.len() == key.key_size()` but any trailing zero
///    padding is accepted as the spec allows the field to be zero-
///    extended to the modulus size)
/// 2. Compute m = c^d mod n
/// 3. Output in little-endian, zero-padded to `key.key_size()`. The
///    caller extracts `client_random = plaintext[0..32]` per
///    MS-RDPBCGR §5.3.4.1 (the 32-byte client random is the low-order
///    bytes; the remainder is zero padding the client added to fill
///    the modulus).
///
/// This is raw textbook RSA -- no PKCS#1 padding is stripped because
/// RDP's Security Exchange PDU does not use PKCS#1 formatting; the
/// client simply pads the 32-byte random to modulus size with zero
/// bytes and raises to `e` mod `n`.
pub fn rsa_private_decrypt_rdp(key: &RsaPrivateKey, ciphertext: &[u8]) -> Vec<u8> {
    let k = key.key_size();
    let c = BigUint::from_le_bytes(ciphertext);
    let m = c.mod_exp(&key.d, &key.n);
    m.to_le_bytes_padded(k)
}

/// Verify an RSA PKCS#1 v1.5 (SHA-256) signature.
///
/// 1. Compute s^e mod n to recover the padded message
/// 2. Reconstruct expected padded message and compare in constant time
///
/// Note: `mod_exp` with a public exponent `e` is not timing-sensitive since
/// `e` is publicly known (typically 65537).
pub fn rsa_verify_sha256(key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool {
    let k = key.key_size();

    if signature.len() != k {
        return false;
    }

    // RSA public key operation: em = signature^e mod n
    let s = BigUint::from_be_bytes(signature);
    let m = s.mod_exp(&key.e, &key.n);
    let em = m.to_be_bytes_padded(k);

    // Constant-time PKCS#1 v1.5 verification (RFC 8017 §8.2.2).
    // Reconstruct expected padded message and compare in constant time,
    // rather than parsing the padding (which leaks structure via timing).

    // Hash the data and build expected PKCS#1 v1.5 encoded message
    let mut hasher = Sha256::new();
    hasher.update(data);
    let actual_hash = hasher.finalize();

    let expected_em = match build_pkcs1_em(k, &actual_hash) {
        Some(em) => em,
        None => return false,
    };

    // Constant-time comparison of entire EM
    let mut diff = 0u8;
    for (a, b) in em.iter().zip(expected_em.iter()) {
        diff |= a ^ b;
    }
    diff == 0
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
    fn pkcs1_v15_pad_minimum_modulus_succeeds() {
        // 512-bit key: k=64, t_len=51, ps_len=10 ≥ 8 → just enough.
        let pad = pkcs1_v15_pad_sha256_digest(64, &[0u8; 32]).unwrap();
        assert_eq!(pad.len(), 64);
        assert_eq!(pad[0], 0x00);
        assert_eq!(pad[1], 0x01);
        // 10 bytes of 0xFF padding
        assert_eq!(&pad[2..12], &[0xFF; 10]);
        assert_eq!(pad[12], 0x00); // separator
        // DigestInfo prefix
        assert_eq!(pad[13], 0x30);
    }

    #[test]
    fn pkcs1_v15_pad_undersized_modulus_returns_none() {
        // 61-byte modulus: 51 + 11 = 62, so 61 is too small.
        assert!(pkcs1_v15_pad_sha256_digest(61, &[0u8; 32]).is_none());
    }

    #[test]
    fn rsa_sign_sha256_digest_matches_rsa_sign_sha256() {
        // sha256(data) → sign vs sign(data) directly should produce
        // identical signatures (PKCS#1 v1.5 is deterministic).
        let key = test_512bit_key();
        let data = b"Hello, PKINIT!";
        let mut hasher = crate::crypto::Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let sig_via_digest = rsa_sign_sha256_digest(&key, &digest).unwrap();
        let sig_via_data = rsa_sign_sha256(&key, data).unwrap();
        assert_eq!(sig_via_digest, sig_via_data);
    }

    #[test]
    fn rsa_sign_verify_roundtrip() {
        let key = test_512bit_key();
        let data = b"Hello, PKINIT!";

        let signature = rsa_sign_sha256(&key, data).unwrap();
        assert_eq!(signature.len(), 64); // 512-bit key = 64 bytes

        let public_key = key.public_key();
        assert!(rsa_verify_sha256(&public_key, data, &signature));
    }

    #[test]
    fn rsa_verify_wrong_data_fails() {
        let key = test_512bit_key();
        let signature = rsa_sign_sha256(&key, b"correct data").unwrap();

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

    #[test]
    fn rsa_public_encrypt_rdp_known_answer() {
        // Textbook RSA: n=33, e=3. plaintext=2 → 2^3 mod 33 = 8
        let pub_key = RsaPublicKey {
            n: BigUint::from_u32(33),
            e: BigUint::from_u32(3),
        };
        let ct = rsa_public_encrypt_rdp(&pub_key, &[0x02]); // 2 in LE
        assert_eq!(ct[0], 0x08); // 8 in LE
    }

    #[test]
    fn rsa_private_decrypt_rdp_roundtrip_via_public_encrypt() {
        // End-to-end: client encrypts a 32-byte random with the server's
        // public key; server decrypts with the private key and must
        // recover the same 32-byte random in the low-order output bytes.
        let priv_key = test_512bit_key();
        let pub_key = priv_key.public_key();
        let mut client_random = [0u8; 32];
        for (i, b) in client_random.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(0x11);
        }

        // Client pads to modulus size (64) with trailing zeros per §5.3.4.1.
        let mut padded = [0u8; 64];
        padded[..32].copy_from_slice(&client_random);
        let encrypted = rsa_public_encrypt_rdp(&pub_key, &padded);
        assert_eq!(encrypted.len(), 64);

        let decrypted = rsa_private_decrypt_rdp(&priv_key, &encrypted);
        assert_eq!(decrypted.len(), 64);
        assert_eq!(&decrypted[..32], &client_random);
        // Padding region is all zero.
        assert!(decrypted[32..].iter().all(|&b| b == 0));
    }

    #[test]
    fn rsa_verify_wrong_length_signature() {
        let key = test_512bit_key();
        let pub_key = key.public_key();
        assert!(!rsa_verify_sha256(&pub_key, b"data", &[0u8; 32])); // too short
        assert!(!rsa_verify_sha256(&pub_key, b"data", &[])); // empty
    }
}
