#![forbid(unsafe_code)]

//! DES and Triple-DES (3DES) block cipher.
//!
//! Pure Rust implementation of DES (FIPS 46-3) and Triple-DES (EDE mode).
//! DES operates on 8-byte blocks with a 56-bit key (8 bytes with parity bits).
//! 3DES uses three 8-byte keys (24 bytes total) in Encrypt-Decrypt-Encrypt order.
//!
//! Also provides CBC mode for 3DES as required by FIPS 140-1 Standard RDP Security.

use alloc::vec::Vec;

use crate::error::{CryptoError, CryptoResult};

// ── DES Tables ──

/// Initial Permutation (IP).
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
];

/// Final Permutation (IP^-1).
const FP: [u8; 64] = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
];

/// Expansion permutation (E).
const E: [u8; 48] = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
];

/// Permutation (P) applied after S-box substitution.
const P: [u8; 32] = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25,
];

/// Permuted Choice 1 (PC-1) -- key schedule.
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
];

/// Permuted Choice 2 (PC-2) -- subkey selection.
const PC2: [u8; 48] = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
];

/// Number of left shifts per round.
const SHIFTS: [u8; 16] = [
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
];

/// S-boxes (8 × 4 × 16).
const SBOXES: [[u8; 64]; 8] = [
    [
        14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7,
         0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
         4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
        15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13,
    ],
    [
        15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
         3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
         0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
        13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9,
    ],
    [
        10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
        13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
         1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12,
    ],
    [
         7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15,
        13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9,
        10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4,
         3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14,
    ],
    [
         2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9,
        14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6,
         4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14,
        11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3,
    ],
    [
        12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11,
        10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8,
         9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6,
         4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13,
    ],
    [
         4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1,
        13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6,
         1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2,
         6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12,
    ],
    [
        13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7,
         1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2,
         7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8,
         2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11,
    ],
];

// ── Bit manipulation helpers ──

/// Apply a permutation table to a u64 value.
fn permute(val: u64, table: &[u8], in_bits: u8) -> u64 {
    let out_len = table.len();
    let mut result: u64 = 0;
    for (i, &pos) in table.iter().enumerate() {
        // pos is 1-based, referring to bit position in the input
        let bit = (val >> (in_bits - pos)) & 1;
        result |= bit << (out_len - 1 - i);
    }
    result
}

// ── DES Key Schedule ──

/// Generate 16 48-bit subkeys from a 64-bit DES key (with parity bits).
fn des_key_schedule(key: u64) -> [u64; 16] {
    // Apply PC-1 to get 56 bits
    let pc1_out = permute(key, &PC1, 64);

    // Split into C and D halves (28 bits each)
    let mut c = (pc1_out >> 28) & 0x0FFF_FFFF;
    let mut d = pc1_out & 0x0FFF_FFFF;

    let mut subkeys = [0u64; 16];

    for round in 0..16 {
        // Left rotate C and D by SHIFTS[round] positions
        let shift = SHIFTS[round] as u32;
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFF_FFFF;
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFF_FFFF;

        // Combine and apply PC-2 to get 48-bit subkey
        let cd = (c << 28) | d;
        subkeys[round] = permute(cd, &PC2, 56);
    }

    subkeys
}

// ── DES Core ──

/// DES Feistel function f(R, K).
fn des_f(r: u32, subkey: u64) -> u32 {
    // Expand R from 32 to 48 bits
    let r64 = r as u64;
    let mut expanded: u64 = 0;
    for (i, &pos) in E.iter().enumerate() {
        let bit = (r64 >> (32 - pos)) & 1;
        expanded |= bit << (47 - i);
    }

    // XOR with subkey
    let xored = expanded ^ subkey;

    // S-box substitution: 48 bits → 32 bits
    // FIPS 46-3 §3.2 — Bit offsets: S[0] at bits 47-42, S[1] at 41-36, ..., S[7] at 5-0
    let mut sbox_out: u32 = 0;
    for i in 0..8 {
        let offset = 42 - i * 6;
        let six_bits = ((xored >> offset) & 0x3F) as u8;

        // Row = bits 0 and 5 combined
        let row = ((six_bits >> 4) & 0x02) | (six_bits & 0x01);
        // Column = bits 1-4
        let col = (six_bits >> 1) & 0x0F;

        let val = SBOXES[i as usize][(row * 16 + col) as usize];
        sbox_out |= (val as u32) << (28 - i * 4);
    }

    // Apply permutation P
    let mut p_out: u32 = 0;
    for (i, &pos) in P.iter().enumerate() {
        let bit = (sbox_out >> (32 - pos)) & 1;
        p_out |= bit << (31 - i);
    }

    p_out
}

/// DES encrypt a single 64-bit block.
fn des_encrypt_block(block: u64, subkeys: &[u64; 16]) -> u64 {
    // Initial permutation
    let ip_out = permute(block, &IP, 64);

    let mut l = (ip_out >> 32) as u32;
    let mut r = ip_out as u32;

    // 16 Feistel rounds
    for round in 0..16 {
        let new_r = l ^ des_f(r, subkeys[round]);
        l = r;
        r = new_r;
    }

    // Combine (note: swap L and R)
    let pre_fp = ((r as u64) << 32) | (l as u64);

    // Final permutation
    permute(pre_fp, &FP, 64)
}

/// DES decrypt a single 64-bit block (reverse subkey order).
fn des_decrypt_block(block: u64, subkeys: &[u64; 16]) -> u64 {
    let ip_out = permute(block, &IP, 64);

    let mut l = (ip_out >> 32) as u32;
    let mut r = ip_out as u32;

    // 16 rounds with reversed subkeys
    for round in (0..16).rev() {
        let new_r = l ^ des_f(r, subkeys[round]);
        l = r;
        r = new_r;
    }

    let pre_fp = ((r as u64) << 32) | (l as u64);
    permute(pre_fp, &FP, 64)
}

/// XOR two 8-byte blocks in place.
fn xor_block_8(a: &mut [u8; 8], b: &[u8; 8]) {
    for i in 0..8 { a[i] ^= b[i]; }
}

// ── Public API ──

/// Convert 8 bytes to u64.
fn bytes_to_u64(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for &byte in &b[..8] {
        v = (v << 8) | byte as u64;
    }
    v
}

/// Convert u64 to 8 bytes.
fn u64_to_bytes(v: u64) -> [u8; 8] {
    [
        (v >> 56) as u8, (v >> 48) as u8, (v >> 40) as u8, (v >> 32) as u8,
        (v >> 24) as u8, (v >> 16) as u8, (v >>  8) as u8, v as u8,
    ]
}

/// Triple-DES (3DES EDE) cipher.
///
/// Uses three 8-byte DES keys (K1, K2, K3) for a total of 24 bytes.
/// - Encrypt: C = E_K3(D_K2(E_K1(P)))  (NIST SP 800-67 EDE)
/// - Decrypt: P = D_K1(E_K2(D_K3(C)))
#[derive(Clone)]
pub struct TripleDes {
    subkeys1: [u64; 16],
    subkeys2: [u64; 16],
    subkeys3: [u64; 16],
}

impl TripleDes {
    /// Create a new 3DES cipher with a 24-byte key (K1 || K2 || K3).
    pub fn new(key: &[u8; 24]) -> Self {
        let k1 = bytes_to_u64(&key[0..8]);
        let k2 = bytes_to_u64(&key[8..16]);
        let k3 = bytes_to_u64(&key[16..24]);

        Self {
            subkeys1: des_key_schedule(k1),
            subkeys2: des_key_schedule(k2),
            subkeys3: des_key_schedule(k3),
        }
    }

    /// Encrypt a single 8-byte block.
    pub fn encrypt_block(&self, plaintext: &[u8; 8]) -> [u8; 8] {
        let block = bytes_to_u64(plaintext);
        // EDE: Encrypt with K1, Decrypt with K2, Encrypt with K3
        let step1 = des_encrypt_block(block, &self.subkeys1);
        let step2 = des_decrypt_block(step1, &self.subkeys2);
        let step3 = des_encrypt_block(step2, &self.subkeys3);
        u64_to_bytes(step3)
    }

    /// Decrypt a single 8-byte block.
    pub fn decrypt_block(&self, ciphertext: &[u8; 8]) -> [u8; 8] {
        let block = bytes_to_u64(ciphertext);
        // DED: Decrypt with K3, Encrypt with K2, Decrypt with K1
        let step1 = des_decrypt_block(block, &self.subkeys3);
        let step2 = des_encrypt_block(step1, &self.subkeys2);
        let step3 = des_decrypt_block(step2, &self.subkeys1);
        u64_to_bytes(step3)
    }

    /// Encrypt data in CBC mode.
    ///
    /// Input must be a non-empty multiple of 8 bytes. IV is 8 bytes.
    /// Returns ciphertext (same length as input).
    pub fn encrypt_cbc(&self, data: &[u8], iv: &[u8; 8]) -> CryptoResult<Vec<u8>> {
        if data.is_empty() || data.len() % 8 != 0 {
            return Err(CryptoError::InvalidDataLength);
        }

        let mut result = Vec::with_capacity(data.len());
        let mut prev = *iv;

        for chunk in data.chunks_exact(8) {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            xor_block_8(&mut block, &prev);
            let encrypted = self.encrypt_block(&block);
            result.extend_from_slice(&encrypted);
            prev = encrypted;
        }

        Ok(result)
    }

    /// Decrypt data in CBC mode.
    ///
    /// Input must be a non-empty multiple of 8 bytes. IV is 8 bytes.
    /// Returns plaintext (same length as input).
    pub fn decrypt_cbc(&self, data: &[u8], iv: &[u8; 8]) -> CryptoResult<Vec<u8>> {
        if data.is_empty() || data.len() % 8 != 0 {
            return Err(CryptoError::InvalidDataLength);
        }

        let mut result = Vec::with_capacity(data.len());
        let mut prev = *iv;

        for chunk in data.chunks_exact(8) {
            let mut ct_block = [0u8; 8];
            ct_block.copy_from_slice(chunk);
            let mut plaintext = self.decrypt_block(&ct_block);
            xor_block_8(&mut plaintext, &prev);
            result.extend_from_slice(&plaintext);
            prev = ct_block;
        }

        Ok(result)
    }
}

impl Drop for TripleDes {
    fn drop(&mut self) {
        self.subkeys1.fill(0);
        self.subkeys2.fill(0);
        self.subkeys3.fill(0);
        core::hint::black_box(&self.subkeys1);
        core::hint::black_box(&self.subkeys2);
        core::hint::black_box(&self.subkeys3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST SP 800-67 test vector for 3DES
    // Key1 = 0133457799BBCDFF
    // Key2 = 0133457799BBCDFF (same for 2-key 3DES, but we test with 3 distinct keys below)
    // Key3 = 0133457799BBCDFF

    #[test]
    fn des_single_block_encrypt_decrypt() {
        // Known DES test vector (FIPS 81)
        // Key = 0123456789ABCDEF
        // Plaintext = 4E6F772069732074 ("Now is t")
        // Ciphertext = 3FA40E8A984D4815
        let key_bytes: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let plaintext: [u8; 8] = [0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74];
        let expected_ct: [u8; 8] = [0x3F, 0xA4, 0x0E, 0x8A, 0x98, 0x4D, 0x48, 0x15];

        let key = bytes_to_u64(&key_bytes);
        let subkeys = des_key_schedule(key);

        let block = bytes_to_u64(&plaintext);
        let ct = des_encrypt_block(block, &subkeys);
        assert_eq!(u64_to_bytes(ct), expected_ct);

        let pt = des_decrypt_block(ct, &subkeys);
        assert_eq!(u64_to_bytes(pt), plaintext);
    }

    #[test]
    fn triple_des_roundtrip() {
        let key: [u8; 24] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        ];
        let plaintext: [u8; 8] = [0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74];

        let cipher = TripleDes::new(&key);
        let ct = cipher.encrypt_block(&plaintext);
        let pt = cipher.decrypt_block(&ct);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn triple_des_cbc_roundtrip() {
        let key: [u8; 24] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        ];
        let iv = [0u8; 8];
        let plaintext = [
            0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
            0x68, 0x65, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x20,
        ]; // "Now is the time "

        let cipher = TripleDes::new(&key);
        let ct = cipher.encrypt_cbc(&plaintext, &iv).unwrap();
        assert_eq!(ct.len(), 16);
        assert_ne!(&ct[..], &plaintext[..]);

        let pt = cipher.decrypt_cbc(&ct, &iv).unwrap();
        assert_eq!(&pt[..], &plaintext[..]);
    }

    #[test]
    fn triple_des_known_vector() {
        // NIST SP 800-67 Appendix B
        // Key1 = 0123456789ABCDEF, Key2 = 23456789ABCDEF01, Key3 = 456789ABCDEF0123
        // Plaintext = "The qufc" → 5468652071756663
        // (We use this to verify our EDE logic is correct)
        let key: [u8; 24] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
            0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
        ];
        let plaintext: [u8; 8] = [0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x66, 0x63];

        let cipher = TripleDes::new(&key);
        let ct = cipher.encrypt_block(&plaintext);
        let pt = cipher.decrypt_block(&ct);

        // Verify roundtrip
        assert_eq!(pt, plaintext);
        // Ciphertext should differ from plaintext
        assert_ne!(ct, plaintext);
    }

    #[test]
    fn triple_des_nist_sp800_67_known_ciphertext() {
        // NIST SP 800-67 Appendix B
        // Key1=0123456789ABCDEF, Key2=23456789ABCDEF01, Key3=456789ABCDEF0123
        // Plaintext="The qufc" (0x5468652071756663)
        // Expected ciphertext=0xA826FD8CE53B855F
        let key: [u8; 24] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
            0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
        ];
        let plaintext: [u8; 8] = [0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x66, 0x63];
        let expected_ct: [u8; 8] = [0xA8, 0x26, 0xFD, 0x8C, 0xE5, 0x3B, 0x85, 0x5F];

        let cipher = TripleDes::new(&key);
        let ct = cipher.encrypt_block(&plaintext);
        assert_eq!(ct, expected_ct);
        assert_eq!(cipher.decrypt_block(&expected_ct), plaintext);
    }
}
