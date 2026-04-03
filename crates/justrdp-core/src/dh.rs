#![forbid(unsafe_code)]

//! Diffie-Hellman key exchange for PKINIT.
//!
//! Implements DH key agreement using the well-known Oakley Group 14
//! (2048-bit MODP group, RFC 3526) as required by PKINIT (RFC 4556).

use crate::bignum::BigUint;

/// Well-known Oakley Group 14 (2048-bit MODP, RFC 3526).
///
/// p = 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
/// g = 2
pub struct OakleyGroup14;

impl OakleyGroup14 {
    /// The 2048-bit prime modulus.
    pub fn prime() -> BigUint {
        BigUint::from_be_bytes(&OAKLEY_GROUP_14_PRIME)
    }

    /// The generator (g = 2).
    pub fn generator() -> BigUint {
        BigUint::from_u32(2)
    }

    /// Key size in bytes (256 bytes for 2048-bit).
    pub fn key_size() -> usize {
        256
    }
}

/// DH key pair.
pub struct DhKeyPair {
    /// Private key (random exponent).
    pub private_key: BigUint,
    /// Public key (g^x mod p).
    pub public_key: BigUint,
}

impl Drop for DhKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// Compute a DH public key: g^x mod p.
pub fn dh_compute_public(g: &BigUint, x: &BigUint, p: &BigUint) -> BigUint {
    g.mod_exp(x, p)
}

/// Compute the DH shared secret: other_public^my_private mod p.
pub fn dh_compute_shared(other_public: &BigUint, my_private: &BigUint, p: &BigUint) -> BigUint {
    other_public.mod_exp(my_private, p)
}

/// Generate a DH key pair from a random private exponent.
///
/// The caller must provide a cryptographically random `private_bytes`
/// (at least 32 bytes, ideally 256 bytes for 2048-bit DH).
pub fn dh_generate_keypair(private_bytes: &[u8]) -> DhKeyPair {
    let p = OakleyGroup14::prime();
    let g = OakleyGroup14::generator();
    let x = BigUint::from_be_bytes(private_bytes).rem(&p);
    let public_key = dh_compute_public(&g, &x, &p);

    DhKeyPair {
        private_key: x,
        public_key,
    }
}

// Oakley Group 14 prime (2048-bit), RFC 3526 Section 3.
#[rustfmt::skip]
const OAKLEY_GROUP_14_PRIME: [u8; 256] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
    0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
    0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
    0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oakley_group14_prime_is_correct_size() {
        let p = OakleyGroup14::prime();
        assert_eq!(p.bit_len(), 2048);
    }

    #[test]
    fn dh_key_exchange_roundtrip() {
        // Use small private keys for test speed
        // In production, these would be 256-byte random values
        let alice_private = BigUint::from_u32(12345);
        let bob_private = BigUint::from_u32(67890);

        let p = OakleyGroup14::prime();
        let g = OakleyGroup14::generator();

        let alice_public = dh_compute_public(&g, &alice_private, &p);
        let bob_public = dh_compute_public(&g, &bob_private, &p);

        let alice_shared = dh_compute_shared(&bob_public, &alice_private, &p);
        let bob_shared = dh_compute_shared(&alice_public, &bob_private, &p);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn dh_generate_keypair_produces_valid_key() {
        let private_bytes = [0x42u8; 32];
        let kp = dh_generate_keypair(&private_bytes);

        let p = OakleyGroup14::prime();
        assert!(kp.public_key < p);
        assert!(!kp.public_key.is_zero());
    }

    #[test]
    fn dh_shared_secret_bytes() {
        let a = BigUint::from_u32(111);
        let b = BigUint::from_u32(222);

        let p = OakleyGroup14::prime();
        let g = OakleyGroup14::generator();

        let a_pub = dh_compute_public(&g, &a, &p);
        let b_pub = dh_compute_public(&g, &b, &p);

        let shared_a = dh_compute_shared(&b_pub, &a, &p);
        let shared_b = dh_compute_shared(&a_pub, &b, &p);

        let bytes_a = shared_a.to_be_bytes_padded(256);
        let bytes_b = shared_b.to_be_bytes_padded(256);

        assert_eq!(bytes_a.len(), 256);
        assert_eq!(bytes_a, bytes_b);
    }
}
