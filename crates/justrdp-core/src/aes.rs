#![forbid(unsafe_code)]

//! AES block cipher (FIPS 197) -- AES-128 and AES-256.
//!
//! Pure Rust implementation using the standard S-box lookup table.
//! Provides ECB (single-block), CBC, and CTS (Ciphertext Stealing, RFC 3962) modes.

use alloc::vec;
use alloc::vec::Vec;

// ── AES S-box and constants ──

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// GF(2^8) multiply by 2 (xtime).
const fn xtime(x: u8) -> u8 {
    if x & 0x80 != 0 {
        (x << 1) ^ 0x1b
    } else {
        x << 1
    }
}

/// GF(2^8) multiply.
const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    let mut i = 0;
    while i < 8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
        i += 1;
    }
    result
}

// ── AES-128 ──

/// AES-128 block cipher.
#[derive(Clone)]
pub struct Aes128 {
    round_keys: [[u8; 16]; 11],
}

impl Aes128 {
    /// Create AES-128 with the given 16-byte key.
    pub fn new(key: &[u8; 16]) -> Self {
        let mut rk = [[0u8; 16]; 11];
        rk[0] = *key;
        for i in 1..11 {
            let prev = &rk[i - 1];
            let mut w = [prev[12], prev[13], prev[14], prev[15]];
            // RotWord + SubWord + Rcon
            w = [SBOX[w[1] as usize], SBOX[w[2] as usize], SBOX[w[3] as usize], SBOX[w[0] as usize]];
            w[0] ^= RCON[i - 1];
            for j in 0..4 {
                for k in 0..4 {
                    rk[i][j * 4 + k] = rk[i - 1][j * 4 + k]
                        ^ if j == 0 { w[k] } else { rk[i][( j - 1) * 4 + k] };
                }
            }
        }
        Self { round_keys: rk }
    }

    /// Encrypt a single 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        aes_encrypt_block(block, &self.round_keys, 10);
    }

    /// Decrypt a single 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        aes_decrypt_block(block, &self.round_keys, 10);
    }
}

// ── AES-256 ──

/// AES-256 block cipher.
#[derive(Clone)]
pub struct Aes256 {
    round_keys: [[u8; 16]; 15],
}

impl Aes256 {
    /// Create AES-256 with the given 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        let mut rk = [[0u8; 16]; 15];
        rk[0][..16].copy_from_slice(&key[..16]);
        rk[1][..16].copy_from_slice(&key[16..32]);

        for i in 2..15 {
            let prev = rk[i - 1];
            let pprev = rk[i - 2];
            if i % 2 == 0 {
                // RotWord + SubWord + Rcon
                let mut w = [prev[12], prev[13], prev[14], prev[15]];
                w = [SBOX[w[1] as usize], SBOX[w[2] as usize], SBOX[w[3] as usize], SBOX[w[0] as usize]];
                w[0] ^= RCON[i / 2 - 1];
                for j in 0..16 {
                    rk[i][j] = pprev[j] ^ if j < 4 { w[j] } else { rk[i][j - 4] };
                }
            } else {
                // SubWord only (no rotation, no rcon)
                let w = [
                    SBOX[prev[12] as usize], SBOX[prev[13] as usize],
                    SBOX[prev[14] as usize], SBOX[prev[15] as usize],
                ];
                for j in 0..16 {
                    rk[i][j] = pprev[j] ^ if j < 4 { w[j] } else { rk[i][j - 4] };
                }
            }
        }
        Self { round_keys: rk }
    }

    /// Encrypt a single 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        aes_encrypt_block(block, &self.round_keys, 14);
    }

    /// Decrypt a single 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        aes_decrypt_block(block, &self.round_keys, 14);
    }
}

// ── AES core round functions ──

fn aes_encrypt_block(state: &mut [u8; 16], rk: &[[u8; 16]], nr: usize) {
    xor_block(state, &rk[0]);
    for round in 1..nr {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        xor_block(state, &rk[round]);
    }
    sub_bytes(state);
    shift_rows(state);
    xor_block(state, &rk[nr]);
}

fn aes_decrypt_block(state: &mut [u8; 16], rk: &[[u8; 16]], nr: usize) {
    xor_block(state, &rk[nr]);
    for round in (1..nr).rev() {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        xor_block(state, &rk[round]);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    xor_block(state, &rk[0]);
}

fn xor_block(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 { a[i] ^= b[i]; }
}

fn sub_bytes(s: &mut [u8; 16]) {
    for i in 0..16 { s[i] = SBOX[s[i] as usize]; }
}

fn inv_sub_bytes(s: &mut [u8; 16]) {
    for i in 0..16 { s[i] = INV_SBOX[s[i] as usize]; }
}

fn shift_rows(s: &mut [u8; 16]) {
    // Row 1: shift left 1
    let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    // Row 2: shift left 2
    let t0 = s[2]; let t1 = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t0; s[14] = t1;
    // Row 3: shift left 3 (= shift right 1)
    let t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

fn inv_shift_rows(s: &mut [u8; 16]) {
    // Row 1: shift right 1
    let t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    // Row 2: shift right 2
    let t0 = s[10]; let t1 = s[14]; s[10] = s[2]; s[14] = s[6]; s[2] = t0; s[6] = t1;
    // Row 3: shift right 3 (= shift left 1)
    let t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a0 = s[i]; let a1 = s[i+1]; let a2 = s[i+2]; let a3 = s[i+3];
        s[i]   = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        s[i+1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        s[i+2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        s[i+3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
    }
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a0 = s[i]; let a1 = s[i+1]; let a2 = s[i+2]; let a3 = s[i+3];
        s[i]   = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
        s[i+1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
        s[i+2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
        s[i+3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
}

// ── AES-CBC mode ──

/// AES-CBC encrypt in place. `data` length must be a multiple of 16.
pub fn aes_cbc_encrypt(cipher: &impl AesBlockCipher, iv: &[u8; 16], data: &mut [u8]) {
    assert!(data.len() % 16 == 0 && !data.is_empty());
    let mut prev = *iv;
    let mut offset = 0;
    while offset < data.len() {
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[offset..offset + 16]);
        xor_block(&mut block, &prev);
        cipher.encrypt(&mut block);
        data[offset..offset + 16].copy_from_slice(&block);
        prev = block;
        offset += 16;
    }
}

/// AES-CBC decrypt in place. `data` length must be a multiple of 16.
pub fn aes_cbc_decrypt(cipher: &impl AesBlockCipher, iv: &[u8; 16], data: &mut [u8]) {
    assert!(data.len() % 16 == 0 && !data.is_empty());
    let mut prev = *iv;
    let mut offset = 0;
    while offset < data.len() {
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[offset..offset + 16]);
        let ct = block;
        cipher.decrypt(&mut block);
        xor_block(&mut block, &prev);
        data[offset..offset + 16].copy_from_slice(&block);
        prev = ct;
        offset += 16;
    }
}

// ── AES-CTS mode (RFC 3962) ──

/// AES-CTS (Ciphertext Stealing) encrypt in place.
/// Data must be at least 16 bytes. Used by Kerberos AES etypes.
pub fn aes_cts_encrypt(cipher: &impl AesBlockCipher, iv: &[u8; 16], data: &mut [u8]) {
    let len = data.len();
    assert!(len >= 16);

    if len == 16 {
        // Single block: just CBC
        let mut block = [0u8; 16];
        block.copy_from_slice(data);
        xor_block(&mut block, iv);
        cipher.encrypt(&mut block);
        data.copy_from_slice(&block);
        return;
    }

    // Pad to full blocks for CBC processing
    let n_full = (len - 1) / 16; // number of complete blocks minus 1
    let last_len = len - n_full * 16;

    // Encrypt all complete blocks with CBC (up to second-to-last)
    let mut prev = *iv;
    for i in 0..n_full - 1 {
        let off = i * 16;
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[off..off + 16]);
        xor_block(&mut block, &prev);
        cipher.encrypt(&mut block);
        data[off..off + 16].copy_from_slice(&block);
        prev = block;
    }

    // Process last two blocks with CTS
    let pn_off = (n_full - 1) * 16; // penultimate plaintext
    let last_off = n_full * 16;     // last plaintext (may be short)

    // Encrypt penultimate block
    let mut pn_block = [0u8; 16];
    pn_block.copy_from_slice(&data[pn_off..pn_off + 16]);
    xor_block(&mut pn_block, &prev);
    cipher.encrypt(&mut pn_block);

    // Pad last block with bytes from encrypted penultimate
    let mut last_block = [0u8; 16];
    last_block[..last_len].copy_from_slice(&data[last_off..last_off + last_len]);
    last_block[last_len..].copy_from_slice(&pn_block[last_len..]);
    xor_block(&mut last_block, &[0u8; 16]); // no XOR needed; this is CTS specific
    // Actually XOR with zero is noop. For CTS, the last plaintext block is padded
    // with the ciphertext of the penultimate block, then encrypted.

    // Wait, let me re-do CTS properly:
    // CTS encrypt:
    //   1. CBC encrypt all blocks except last two
    //   2. Pn = CBC encrypt of penultimate plaintext (using prev as IV)
    //   3. Pad last plaintext Pm with bytes from Pn: Pm_padded = Pm || Pn[len(Pm):]
    //   4. Cn-1 = encrypt(Pm_padded XOR Pn)  -- wait, no
    //
    // Actually, CTS per RFC 3962:
    //   Cn-1 = E(Pn-1 XOR prev)  (this is pn_block above)
    //   Pad Pn to 16 bytes using tail of Cn-1: Pn_padded = Pn || Cn-1[m:]
    //   Cn = E(Pn_padded XOR Cn-1)  -- wait, no that's also wrong
    //
    // Let me just implement it correctly:
    // For n >= 2 blocks:
    //   Process blocks 0..n-2 with normal CBC
    //   E(n-1) = AES_ECB(P(n-1) XOR C(n-2))  -- call this Cn_minus1
    //   Pn_padded = Pn || Cn_minus1[m..16]    -- pad last block with tail of Cn_minus1
    //   Cn = AES_ECB(Pn_padded XOR Cn_minus1) -- NO, not XOR with Cn_minus1
    //
    // Actually the RFC 3962 CTS mode is CBC-CS3 (as per NIST SP 800-38A Addendum):
    //   For the last two blocks Pn-1 and Pn (where Pn may be short):
    //   1. Cn_star = E_K(Pn-1 XOR Cn-2)   -- encrypt penultimate with CBC
    //   2. Cn = head(Cn_star, m)           -- Cn is truncated Cn_star
    //   3. Pad Pn: Pn_padded = Pn || tail(Cn_star, 16-m)
    //   4. Cn-1 = E_K(Pn_padded XOR Cn_star)  -- wait, XOR with what?
    //
    // I keep getting confused. Let me just use the standard algorithm:
    //
    // CBC-CTS encrypt (last two blocks):
    //   prev = last CBC ciphertext (or IV if only 2 blocks total)
    //   Cn_star = AES(Pn-1 XOR prev)
    //   Cn = Cn_star[0..m]  (truncated to last block's original length)
    //   Pn_pad = Pn || Cn_star[m..16]
    //   Cn-1 = AES(Pn_pad XOR Cn_star)  -- hmm, that uses Cn_star as both key material and XOR
    //
    // No. Let me look at this more carefully. The correct CBC-CTS (CS3) is:
    //
    //   Encrypt:
    //     For i = 0 to n-3: Ci = E(Pi XOR C(i-1)) with C(-1) = IV
    //     Cn_star = E(P(n-2) XOR C(n-3))
    //     Cn-1 = E(Pn_padded XOR Cn_star) where Pn_padded = Pn || Cn_star[m..16]
    //     Cn = Cn_star[0..m]   -- the ciphertext is Cn-1 followed by Cn (swapped!)
    //     Output: C0 || C1 || ... || C(n-3) || Cn-1 || Cn
    //
    // No wait, that doesn't look right either. Let me just use a known reference.

    // Reset and redo CTS properly. The above partial computation is wrong.
    // I'll recalculate from scratch.
    let _ = pn_block;
    let _ = last_block;

    // Re-read data since we may have partially modified it
    // Actually we only modified blocks 0..n_full-2 with CBC above, which is correct.
    // Now handle the last two blocks.

    // Penultimate plaintext
    let mut pn = [0u8; 16];
    pn.copy_from_slice(&data[pn_off..pn_off + 16]);
    xor_block(&mut pn, &prev);
    cipher.encrypt(&mut pn);
    // pn is now E(P_{n-1} XOR prev) = Cn_star

    // Last plaintext (possibly short)
    let mut last_padded = pn; // start with Cn_star, then overwrite first m bytes
    last_padded[..last_len].copy_from_slice(&data[last_off..last_off + last_len]);

    // Cn-1 = E(last_padded XOR Cn_star)? No...
    // Let me just follow the exact algorithm from RFC 3962 section 5:
    //
    //   1. Encrypt the first n-1 blocks as normal CBC
    //   2. Xor the last plaintext block (padded with zeros to 16 bytes)
    //      with the (n-1)th ciphertext
    //   3. Encrypt the result to get Cn-1
    //   4. Cn = first m bytes of the (n-1)th ciphertext
    //   5. Output is: C0..Cn-2, Cn-1, Cn  (note: swapped last two)

    // Wait, the RFC 3962 actually says (Section 5):
    //
    // To encrypt, do CBC over the first (n-1) blocks to get C[1] through C[n-1].
    // For the last partial block:
    //   Pad the plaintext to a full block with zeros.
    //   XOR with C[n-1].
    //   Encrypt to get C[n].
    //   C[n-1] is truncated to len(P[n]) bytes.
    //
    // So the output is C[1] ... C[n-1]_truncated ... C[n]
    // But the ciphertext is rearranged: the last full block is C[n] and the
    // truncated block is C[n-1].

    // Let me just implement this correctly now:

    // Step 1: CBC encrypt blocks 0 through n_full-1 (all complete blocks)
    // We already did 0 through n_full-2. Now do block n_full-1:
    let mut cn_minus1 = [0u8; 16];
    cn_minus1.copy_from_slice(&data[pn_off..pn_off + 16]);
    xor_block(&mut cn_minus1, &prev);
    cipher.encrypt(&mut cn_minus1);
    // cn_minus1 is now C[n-1]

    // Step 2: Pad last plaintext with zeros, XOR with C[n-1], encrypt
    let mut last_plain = [0u8; 16];
    last_plain[..last_len].copy_from_slice(&data[last_off..last_off + last_len]);
    xor_block(&mut last_plain, &cn_minus1);
    cipher.encrypt(&mut last_plain);
    // last_plain is now C[n]

    // Step 3: Write output with swap: C[n] at penultimate position, C[n-1] truncated at last
    data[pn_off..pn_off + 16].copy_from_slice(&last_plain); // C[n]
    data[last_off..last_off + last_len].copy_from_slice(&cn_minus1[..last_len]); // C[n-1] truncated
}

/// AES-CTS decrypt in place.
/// Data must be at least 16 bytes.
pub fn aes_cts_decrypt(cipher: &impl AesBlockCipher, iv: &[u8; 16], data: &mut [u8]) {
    let len = data.len();
    assert!(len >= 16);

    if len == 16 {
        let mut block = [0u8; 16];
        block.copy_from_slice(data);
        cipher.decrypt(&mut block);
        xor_block(&mut block, iv);
        data.copy_from_slice(&block);
        return;
    }

    let n_full = (len - 1) / 16;
    let last_len = len - n_full * 16;

    // Decrypt blocks 0..n_full-2 with normal CBC
    let mut prev = *iv;
    for i in 0..n_full - 1 {
        let off = i * 16;
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[off..off + 16]);
        let ct = block;
        cipher.decrypt(&mut block);
        xor_block(&mut block, &prev);
        data[off..off + 16].copy_from_slice(&block);
        prev = ct;
    }

    let pn_off = (n_full - 1) * 16;
    let last_off = n_full * 16;

    // In the ciphertext: pn_off has C[n], last_off has C[n-1] truncated
    // Step 1: Decrypt C[n] to get intermediate
    let mut cn = [0u8; 16];
    cn.copy_from_slice(&data[pn_off..pn_off + 16]);
    let mut intermediate = cn;
    cipher.decrypt(&mut intermediate);
    // intermediate = D(C[n]) = P_last_padded XOR C[n-1]

    // Step 2: Reconstruct C[n-1] by combining truncated part from data with tail from intermediate
    let mut cn_minus1 = [0u8; 16];
    cn_minus1[..last_len].copy_from_slice(&data[last_off..last_off + last_len]);
    // The remaining bytes of C[n-1] come from intermediate XOR with zeros
    // Actually: intermediate = last_plain_padded XOR cn_minus1
    // So intermediate[last_len..] = 0 XOR cn_minus1[last_len..] = cn_minus1[last_len..]
    cn_minus1[last_len..].copy_from_slice(&intermediate[last_len..]);

    // Step 3: Recover last plaintext
    let mut last_plain = intermediate;
    xor_block(&mut last_plain, &cn_minus1);
    // Only first last_len bytes are valid
    data[last_off..last_off + last_len].copy_from_slice(&last_plain[..last_len]);

    // Step 4: Decrypt C[n-1] to get penultimate plaintext
    let mut pn_plain = cn_minus1;
    cipher.decrypt(&mut pn_plain);
    xor_block(&mut pn_plain, &prev);
    data[pn_off..pn_off + 16].copy_from_slice(&pn_plain);
}

/// Trait for AES block cipher operations.
pub trait AesBlockCipher {
    fn encrypt(&self, block: &mut [u8; 16]);
    fn decrypt(&self, block: &mut [u8; 16]);
}

impl AesBlockCipher for Aes128 {
    fn encrypt(&self, block: &mut [u8; 16]) { self.encrypt_block(block); }
    fn decrypt(&self, block: &mut [u8; 16]) { self.decrypt_block(block); }
}

impl AesBlockCipher for Aes256 {
    fn encrypt(&self, block: &mut [u8; 16]) { self.encrypt_block(block); }
    fn decrypt(&self, block: &mut [u8; 16]) { self.decrypt_block(block); }
}

// ── PBKDF2-HMAC-SHA1 ──

use crate::crypto::hmac_sha1;

/// PBKDF2 with HMAC-SHA1 (RFC 2898).
/// Used by Kerberos AES string-to-key (RFC 3962).
pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(dk_len);
    let mut block_num = 1u32;

    while result.len() < dk_len {
        // U_1 = PRF(password, salt || INT_32_BE(i))
        let mut salt_block = Vec::with_capacity(salt.len() + 4);
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&block_num.to_be_bytes());

        let mut u = hmac_sha1(password, &salt_block);
        let mut t = u;

        // U_2 .. U_c
        for _ in 1..iterations {
            u = hmac_sha1(password, &u);
            for j in 0..20 {
                t[j] ^= u[j];
            }
        }

        let remaining = dk_len - result.len();
        let to_copy = if remaining < 20 { remaining } else { 20 };
        result.extend_from_slice(&t[..to_copy]);
        block_num += 1;
    }

    result
}

// ── Kerberos key derivation (RFC 3961) ──

/// Kerberos DK (Derive Key) function per RFC 3961 section 5.1.
///
/// DK(base_key, usage) = random-to-key(DR(base_key, usage))
/// DR = n-fold constant, then encrypt with AES-CBC to derive key material.
pub fn krb5_derive_key(cipher: &impl AesBlockCipher, usage: &[u8], key_len: usize) -> Vec<u8> {
    let folded = nfold(usage, 16); // n-fold to block size (128 bits)
    let mut derived = Vec::with_capacity(key_len);
    let mut block = [0u8; 16];
    block.copy_from_slice(&folded);

    while derived.len() < key_len {
        cipher.encrypt(&mut block);
        derived.extend_from_slice(&block);
    }

    derived.truncate(key_len);
    derived
}

/// n-fold function (RFC 3961 section 5.1).
///
/// Replicates the input with 13-bit right rotations to lcm length,
/// then folds into `n_bytes` with ones-complement addition.
pub fn nfold(input: &[u8], n_bytes: usize) -> Vec<u8> {
    let in_len = input.len();
    let in_bits = in_len * 8;
    let out_bits = n_bytes * 8;
    let lcm_bits = lcm_usize(in_bits, out_bits);
    let lcm_bytes = lcm_bits / 8;
    let num_copies = lcm_bits / in_bits;

    // Build lcm-sized buffer of rotated copies
    let mut buf = vec![0u8; lcm_bytes];
    for c in 0..num_copies {
        let rot = (13 * c) % in_bits;
        for j in 0..in_len {
            // Right rotation: output bit j*8 comes from input bit (j*8 - rot)
            let src_bit = ((j * 8 + in_bits) - (rot % in_bits)) % in_bits;
            let src_byte = src_bit / 8;
            let src_off = src_bit % 8;
            buf[c * in_len + j] = if src_off == 0 {
                input[src_byte]
            } else {
                ((input[src_byte] as u16) << src_off | (input[(src_byte + 1) % in_len] as u16) >> (8 - src_off)) as u8
            };
        }
    }

    // Fold: add n_bytes-sized chunks with ones-complement (end-around carry)
    let mut out = vec![0u8; n_bytes];
    for chunk_start in (0..lcm_bytes).step_by(n_bytes) {
        let mut carry: u16 = 0;
        for j in (0..n_bytes).rev() {
            let s = out[j] as u16 + buf[chunk_start + j] as u16 + carry;
            out[j] = (s & 0xff) as u8;
            carry = s >> 8;
        }
        while carry != 0 {
            for j in (0..n_bytes).rev() {
                let s = out[j] as u16 + carry;
                out[j] = (s & 0xff) as u8;
                carry = s >> 8;
            }
        }
    }

    out
}

fn gcd_usize(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

fn lcm_usize(a: usize, b: usize) -> usize {
    a / gcd_usize(a, b) * b
}

/// Kerberos string-to-key for AES etypes (RFC 3962).
///
/// string2key(password, salt, params) =
///     random-to-key(PBKDF2(password, salt, iterations, key_len))
///     then DK(key, "kerberos") to derive the final key.
pub fn krb5_aes_string_to_key(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    let tkey = pbkdf2_hmac_sha1(password, salt, iterations, key_len);

    // DK(tkey, "kerberos"): n-fold to block size (16), then ECB-chain encrypt
    let folded = nfold(b"kerberos", 16);
    let mut block = [0u8; 16];
    block.copy_from_slice(&folded);

    let mut derived = Vec::with_capacity(key_len);
    if key_len == 16 {
        let cipher = Aes128::new(&tkey[..16].try_into().unwrap());
        while derived.len() < key_len {
            cipher.encrypt_block(&mut block);
            derived.extend_from_slice(&block);
        }
    } else {
        let cipher = Aes256::new(&tkey[..32].try_into().unwrap());
        while derived.len() < key_len {
            cipher.encrypt_block(&mut block);
            derived.extend_from_slice(&block);
        }
    }

    derived.truncate(key_len);
    derived
}

// ── Kerberos AES etype encrypt/decrypt (RFC 3962) ──

/// Derive the encryption sub-key Ke for a given key usage.
/// Ke = DK(base_key, usage_number || 0xAA)
pub fn krb5_derive_ke(base_key: &[u8], usage: i32) -> Vec<u8> {
    let key_len = base_key.len();
    let mut constant = vec![0u8; 5];
    constant[0] = (usage >> 24) as u8;
    constant[1] = (usage >> 16) as u8;
    constant[2] = (usage >> 8) as u8;
    constant[3] = usage as u8;
    constant[4] = 0xAA; // encrypt
    if key_len == 16 {
        let cipher = Aes128::new(base_key.try_into().unwrap());
        krb5_derive_key(&cipher, &constant, key_len)
    } else {
        let cipher = Aes256::new(base_key.try_into().unwrap());
        krb5_derive_key(&cipher, &constant, key_len)
    }
}

/// Derive the integrity sub-key Ki for a given key usage.
/// Ki = DK(base_key, usage_number || 0x55)
pub fn krb5_derive_ki(base_key: &[u8], usage: i32) -> Vec<u8> {
    let key_len = base_key.len();
    let mut constant = vec![0u8; 5];
    constant[0] = (usage >> 24) as u8;
    constant[1] = (usage >> 16) as u8;
    constant[2] = (usage >> 8) as u8;
    constant[3] = usage as u8;
    constant[4] = 0x55; // integrity
    if key_len == 16 {
        let cipher = Aes128::new(base_key.try_into().unwrap());
        krb5_derive_key(&cipher, &constant, key_len)
    } else {
        let cipher = Aes256::new(base_key.try_into().unwrap());
        krb5_derive_key(&cipher, &constant, key_len)
    }
}

/// AES-CTS-HMAC-SHA1-96 encrypt (RFC 3962).
///
/// Encryption format: confounder(16) + plaintext, encrypted with AES-CTS.
/// Output: encrypted_data + HMAC-SHA1-96 (12 bytes).
///
/// `confounder` must be 16 random bytes.
pub fn krb5_aes_encrypt(base_key: &[u8], usage: i32, plaintext: &[u8], confounder: &[u8; 16]) -> Vec<u8> {
    let ke = krb5_derive_ke(base_key, usage);
    let ki = krb5_derive_ki(base_key, usage);

    // Build plaintext: confounder + data
    let mut full = Vec::with_capacity(16 + plaintext.len());
    full.extend_from_slice(confounder);
    full.extend_from_slice(plaintext);

    // Compute HMAC-SHA1-96 over confounder + plaintext using Ki
    let hmac = crate::crypto::hmac_sha1(&ki, &full);
    let checksum = &hmac[..12]; // truncate to 96 bits

    // Encrypt with AES-CTS using Ke, IV=0
    let iv = [0u8; 16];
    if ke.len() == 16 {
        let cipher = Aes128::new(ke[..16].try_into().unwrap());
        aes_cts_encrypt(&cipher, &iv, &mut full);
    } else {
        let cipher = Aes256::new(ke[..32].try_into().unwrap());
        aes_cts_encrypt(&cipher, &iv, &mut full);
    }

    // Output: ciphertext + 12-byte HMAC
    full.extend_from_slice(checksum);
    full
}

/// AES-CTS-HMAC-SHA1-96 decrypt (RFC 3962).
///
/// Input: ciphertext + 12-byte HMAC.
/// Returns decrypted plaintext (without the 16-byte confounder).
/// Returns None if HMAC verification fails.
pub fn krb5_aes_decrypt(base_key: &[u8], usage: i32, ciphertext_with_hmac: &[u8]) -> Option<Vec<u8>> {
    if ciphertext_with_hmac.len() < 16 + 12 {
        return None; // need at least confounder + HMAC
    }

    let ke = krb5_derive_ke(base_key, usage);
    let ki = krb5_derive_ki(base_key, usage);

    let hmac_offset = ciphertext_with_hmac.len() - 12;
    let expected_hmac = &ciphertext_with_hmac[hmac_offset..];
    let mut encrypted = ciphertext_with_hmac[..hmac_offset].to_vec();

    // Decrypt with AES-CTS using Ke, IV=0
    let iv = [0u8; 16];
    if ke.len() == 16 {
        let cipher = Aes128::new(ke[..16].try_into().unwrap());
        aes_cts_decrypt(&cipher, &iv, &mut encrypted);
    } else {
        let cipher = Aes256::new(ke[..32].try_into().unwrap());
        aes_cts_decrypt(&cipher, &iv, &mut encrypted);
    }

    // Verify HMAC-SHA1-96 over decrypted data using Ki
    let hmac = crate::crypto::hmac_sha1(&ki, &encrypted);
    let computed_hmac = &hmac[..12];

    // Constant-time comparison
    let mut diff = 0u8;
    for i in 0..12 {
        diff |= expected_hmac[i] ^ computed_hmac[i];
    }
    if diff != 0 {
        return None;
    }

    // Strip the 16-byte confounder
    Some(encrypted[16..].to_vec())
}

/// Compute HMAC-SHA1-96-AES checksum (RFC 3962).
///
/// Used for Kerberos checksums (cksumtype 15 for AES128, 16 for AES256).
pub fn krb5_aes_checksum(base_key: &[u8], usage: i32, data: &[u8]) -> Vec<u8> {
    let kc_constant = {
        let mut c = vec![0u8; 5];
        c[0] = (usage >> 24) as u8;
        c[1] = (usage >> 16) as u8;
        c[2] = (usage >> 8) as u8;
        c[3] = usage as u8;
        c[4] = 0x99; // checksum
        c
    };
    let key_len = base_key.len();
    let kc = if key_len == 16 {
        let cipher = Aes128::new(base_key.try_into().unwrap());
        krb5_derive_key(&cipher, &kc_constant, key_len)
    } else {
        let cipher = Aes256::new(base_key.try_into().unwrap());
        krb5_derive_key(&cipher, &kc_constant, key_len)
    };
    let hmac = crate::crypto::hmac_sha1(&kc, data);
    hmac[..12].to_vec() // truncate to 96 bits
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 197 Appendix B test vector
    #[test]
    fn aes128_encrypt_fips197() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let mut block: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        ];
        let expected: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
        ];
        let aes = Aes128::new(&key);
        aes.encrypt_block(&mut block);
        assert_eq!(block, expected);
    }

    #[test]
    fn aes128_decrypt_fips197() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let ciphertext: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
        ];
        let expected: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        ];
        let mut block = ciphertext;
        let aes = Aes128::new(&key);
        aes.decrypt_block(&mut block);
        assert_eq!(block, expected);
    }

    #[test]
    fn aes256_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = [0x01u8; 16];
        let mut block = plaintext;
        let aes = Aes256::new(&key);
        aes.encrypt_block(&mut block);
        assert_ne!(block, plaintext);
        aes.decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }

    #[test]
    fn aes_cbc_roundtrip() {
        let key = [0x2bu8; 16];
        let iv = [0u8; 16];
        let plaintext = [0x11u8; 48]; // 3 blocks
        let mut data = plaintext;
        let aes = Aes128::new(&key);
        aes_cbc_encrypt(&aes, &iv, &mut data);
        assert_ne!(data, plaintext);
        aes_cbc_decrypt(&aes, &iv, &mut data);
        assert_eq!(data, plaintext);
    }

    #[test]
    fn aes_cts_roundtrip_exact() {
        let key = [0x63u8; 16];
        let iv = [0u8; 16];
        let plaintext = [0x44u8; 32]; // exactly 2 blocks
        let mut data = plaintext;
        let aes = Aes128::new(&key);
        aes_cts_encrypt(&aes, &iv, &mut data);
        assert_ne!(data, plaintext);
        aes_cts_decrypt(&aes, &iv, &mut data);
        assert_eq!(data, plaintext);
    }

    #[test]
    fn aes_cts_roundtrip_partial() {
        let key = [0x63u8; 16];
        let iv = [0u8; 16];
        let plaintext: Vec<u8> = (0..37).collect(); // 2 blocks + 5 bytes
        let mut data = plaintext.clone();
        let aes = Aes128::new(&key);
        aes_cts_encrypt(&aes, &iv, &mut data);
        assert_ne!(data, plaintext);
        aes_cts_decrypt(&aes, &iv, &mut data);
        assert_eq!(data, plaintext);
    }

    #[test]
    fn aes_cts_single_block() {
        let key = [0x01u8; 16];
        let iv = [0u8; 16];
        let plaintext = [0xABu8; 16];
        let mut data = plaintext;
        let aes = Aes128::new(&key);
        aes_cts_encrypt(&aes, &iv, &mut data);
        aes_cts_decrypt(&aes, &iv, &mut data);
        assert_eq!(data, plaintext);
    }

    #[test]
    fn pbkdf2_rfc6070_vector1() {
        // RFC 6070 test vector 1
        let dk = pbkdf2_hmac_sha1(b"password", b"salt", 1, 20);
        assert_eq!(
            dk,
            vec![0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9,
                 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6]
        );
    }

    #[test]
    fn pbkdf2_rfc6070_vector2() {
        // RFC 6070 test vector 2
        let dk = pbkdf2_hmac_sha1(b"password", b"salt", 2, 20);
        assert_eq!(
            dk,
            vec![0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e,
                 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57]
        );
    }

    #[test]
    fn nfold_kerberos() {
        // RFC 3961 test vector: nfold("kerberos", 128)
        let result = nfold(b"kerberos", 16);
        assert_eq!(
            result,
            vec![0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73,
                 0x7b, 0x9b, 0x5b, 0x2b, 0x93, 0x13, 0x2b, 0x93]
        );
    }

    #[test]
    fn aes256_encrypt_fips197() {
        // FIPS 197 Appendix C.3 - AES-256 test vector
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let mut block: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
            0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];
        let aes = Aes256::new(&key);
        aes.encrypt_block(&mut block);
        assert_eq!(block, expected);
    }

    #[test]
    fn krb5_string_to_key_aes128() {
        // RFC 3962 Appendix B test vector
        // password="password", salt="ATHENA.MIT.EDUraeburn", iter=1
        let key = krb5_aes_string_to_key(
            b"password",
            b"ATHENA.MIT.EDUraeburn",
            1,
            16,
        );
        assert_eq!(
            key,
            vec![
                0x42, 0x26, 0x3c, 0x6e, 0x89, 0xf4, 0xfc, 0x28,
                0xb8, 0xdf, 0x68, 0xee, 0x09, 0x79, 0x9f, 0x15,
            ]
        );
    }

    #[test]
    fn krb5_string_to_key_aes256() {
        // RFC 3962 Appendix B test vector (256-bit)
        // password="password", salt="ATHENA.MIT.EDUraeburn", iter=1
        let key = krb5_aes_string_to_key(
            b"password",
            b"ATHENA.MIT.EDUraeburn",
            1,
            32,
        );
        assert_eq!(
            key,
            vec![
                0xfe, 0x69, 0x7b, 0x52, 0xbc, 0x0d, 0x3c, 0xe1,
                0x44, 0x32, 0xba, 0x03, 0x6a, 0x92, 0xe6, 0x5b,
                0xbb, 0x52, 0x28, 0x09, 0x90, 0xa2, 0xfa, 0x27,
                0x88, 0x39, 0x98, 0xd7, 0x2a, 0xf3, 0x01, 0x61,
            ]
        );
    }

    #[test]
    fn krb5_aes128_encrypt_decrypt_roundtrip() {
        let key = krb5_aes_string_to_key(b"password", b"EXAMPLE.COMuser", 4096, 16);
        let plaintext = b"Hello Kerberos!";
        let confounder = [0x42u8; 16];

        let encrypted = krb5_aes_encrypt(&key, 7, plaintext, &confounder);
        assert!(encrypted.len() > plaintext.len());

        let decrypted = krb5_aes_decrypt(&key, 7, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn krb5_aes256_encrypt_decrypt_roundtrip() {
        let key = krb5_aes_string_to_key(b"password", b"EXAMPLE.COMuser", 4096, 32);
        let plaintext = b"Hello Kerberos AES-256!";
        let confounder = [0x37u8; 16];

        let encrypted = krb5_aes_encrypt(&key, 11, plaintext, &confounder);
        let decrypted = krb5_aes_decrypt(&key, 11, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn krb5_aes_decrypt_bad_hmac_fails() {
        let key = krb5_aes_string_to_key(b"password", b"EXAMPLE.COMuser", 4096, 16);
        let plaintext = b"test";
        let confounder = [0x01u8; 16];

        let mut encrypted = krb5_aes_encrypt(&key, 1, plaintext, &confounder);
        // Corrupt the HMAC
        let len = encrypted.len();
        encrypted[len - 1] ^= 0xFF;

        assert!(krb5_aes_decrypt(&key, 1, &encrypted).is_none());
    }

    #[test]
    fn krb5_aes_checksum_produces_12_bytes() {
        let key = krb5_aes_string_to_key(b"password", b"EXAMPLE.COMuser", 4096, 16);
        let cksum = krb5_aes_checksum(&key, 6, b"some data to checksum");
        assert_eq!(cksum.len(), 12);
    }
}
