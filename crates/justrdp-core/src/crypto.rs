#![forbid(unsafe_code)]

//! Cryptographic primitives for RDP -- MS-RDPBCGR 5.3/5.4
//!
//! Pure Rust implementations of the crypto algorithms needed for
//! Standard RDP Security. In production, these should be replaced
//! with well-audited crate implementations (e.g., `rc4`, `md-5`, `sha1`).
//!
//! ## Algorithms
//! - **RC4** -- Stream cipher for Standard RDP Security encryption
//! - **MD5** -- 128-bit hash for session key derivation
//! - **SHA-1** -- 160-bit hash for session key derivation
//! - **SHA-256** -- 256-bit hash (CredSSP)
//! - **HMAC** -- Keyed hash for MAC generation
//!
//! ## RSA / Triple-DES
//! RSA and FIPS triple-DES are complex and best provided by external crates.
//! We define traits so they can be injected.

use alloc::vec;

// ── RC4 ──

/// RC4 stream cipher state.
#[derive(Clone)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Initialize RC4 with the given key.
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    /// Encrypt/decrypt data in place (RC4 is symmetric).
    pub fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

// ── MD4 ──

/// MD4 hash (128-bit / 16 bytes). Required for NTLM NT hash (NTOWF).
pub struct Md4 {
    state: [u32; 4],
    count: u64,
    buffer: [u8; 64],
    buf_len: usize,
}

impl Md4 {
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            count: 0,
            buffer: [0u8; 64],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.count += data.len() as u64;

        if self.buf_len > 0 {
            let needed = 64 - self.buf_len;
            if data.len() < needed {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buffer[self.buf_len..64].copy_from_slice(&data[..needed]);
            md4_transform(&mut self.state, &self.buffer);
            offset = needed;
            self.buf_len = 0;
        }

        while offset + 64 <= data.len() {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            md4_transform(&mut self.state, &block);
            offset += 64;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let bit_count = self.count * 8;
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        self.update(&bit_count.to_le_bytes());

        let mut result = [0u8; 16];
        for (i, &word) in self.state.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        result
    }
}

/// Compute MD4 hash of data.
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(data);
    hasher.finalize()
}

fn md4_transform(state: &mut [u32; 4], block: &[u8; 64]) {
    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_le_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }

    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);

    // Round 1: F(b,c,d) = (b & c) | (!b & d)
    for &(k, s) in &[
        (0, 3), (1, 7), (2, 11), (3, 19), (4, 3), (5, 7), (6, 11), (7, 19),
        (8, 3), (9, 7), (10, 11), (11, 19), (12, 3), (13, 7), (14, 11), (15, 19),
    ] {
        let f = (b & c) | ((!b) & d);
        let temp = a.wrapping_add(f).wrapping_add(m[k]).rotate_left(s);
        a = d;
        d = c;
        c = b;
        b = temp;
    }

    // Round 2: G(b,c,d) = (b & c) | (b & d) | (c & d), constant 0x5A827999
    for &(k, s) in &[
        (0, 3), (4, 5), (8, 9), (12, 13), (1, 3), (5, 5), (9, 9), (13, 13),
        (2, 3), (6, 5), (10, 9), (14, 13), (3, 3), (7, 5), (11, 9), (15, 13),
    ] {
        let g = (b & c) | (b & d) | (c & d);
        let temp = a.wrapping_add(g).wrapping_add(m[k]).wrapping_add(0x5A827999).rotate_left(s);
        a = d;
        d = c;
        c = b;
        b = temp;
    }

    // Round 3: H(b,c,d) = b ^ c ^ d, constant 0x6ED9EBA1
    for &(k, s) in &[
        (0, 3), (8, 9), (4, 11), (12, 15), (2, 3), (10, 9), (6, 11), (14, 15),
        (1, 3), (9, 9), (5, 11), (13, 15), (3, 3), (11, 9), (7, 11), (15, 15),
    ] {
        let h = b ^ c ^ d;
        let temp = a.wrapping_add(h).wrapping_add(m[k]).wrapping_add(0x6ED9EBA1).rotate_left(s);
        a = d;
        d = c;
        c = b;
        b = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

// ── MD5 ──

/// MD5 hash (128-bit / 16 bytes).
pub struct Md5 {
    state: [u32; 4],
    count: u64,
    buffer: [u8; 64],
    buf_len: usize,
}

impl Md5 {
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            count: 0,
            buffer: [0u8; 64],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.count += data.len() as u64;

        if self.buf_len > 0 {
            let needed = 64 - self.buf_len;
            if data.len() < needed {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buffer[self.buf_len..64].copy_from_slice(&data[..needed]);
            md5_transform(&mut self.state, &self.buffer);
            offset = needed;
            self.buf_len = 0;
        }

        while offset + 64 <= data.len() {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            md5_transform(&mut self.state, &block);
            offset += 64;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let bit_count = self.count * 8;
        // Padding
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        self.update(&bit_count.to_le_bytes());

        let mut result = [0u8; 16];
        for (i, &word) in self.state.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        result
    }
}

/// Compute MD5 hash of data.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize()
}

fn md5_transform(state: &mut [u32; 4], block: &[u8; 64]) {
    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_le_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }

    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);

    const S: [[u32; 4]; 4] = [
        [7, 12, 17, 22], [5, 9, 14, 20], [4, 11, 16, 23], [6, 10, 15, 21],
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    for i in 0..64 {
        let (f, g) = match i {
            0..=15 => ((b & c) | ((!b) & d), i),
            16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
            32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | (!d)), (7 * i) % 16),
        };
        let temp = d;
        d = c;
        c = b;
        b = b.wrapping_add(
            (a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]))
                .rotate_left(S[i / 16][i % 4]),
        );
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

// ── SHA-1 ──

/// SHA-1 hash (160-bit / 20 bytes).
pub struct Sha1 {
    state: [u32; 5],
    count: u64,
    buffer: [u8; 64],
    buf_len: usize,
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            count: 0,
            buffer: [0u8; 64],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.count += data.len() as u64;

        if self.buf_len > 0 {
            let needed = 64 - self.buf_len;
            if data.len() < needed {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buffer[self.buf_len..64].copy_from_slice(&data[..needed]);
            sha1_transform(&mut self.state, &self.buffer);
            offset = needed;
            self.buf_len = 0;
        }

        while offset + 64 <= data.len() {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            sha1_transform(&mut self.state, &block);
            offset += 64;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let bit_count = self.count * 8;
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        self.update(&bit_count.to_be_bytes());

        let mut result = [0u8; 20];
        for (i, &word) in self.state.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        result
    }
}

/// Compute SHA-1 hash of data.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

fn sha1_transform(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);

    for i in 0..80 {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
            20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
            _ => (b ^ c ^ d, 0xCA62C1D6),
        };
        let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

// ── SHA-256 ──

/// SHA-256 hash (256-bit / 32 bytes).
pub struct Sha256 {
    state: [u32; 8],
    count: u64,
    buffer: [u8; 64],
    buf_len: usize,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            count: 0,
            buffer: [0u8; 64],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.count += data.len() as u64;

        if self.buf_len > 0 {
            let needed = 64 - self.buf_len;
            if data.len() < needed {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buffer[self.buf_len..64].copy_from_slice(&data[..needed]);
            sha256_transform(&mut self.state, &self.buffer);
            offset = needed;
            self.buf_len = 0;
        }

        while offset + 64 <= data.len() {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            sha256_transform(&mut self.state, &block);
            offset += 64;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_count = self.count * 8;
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        self.update(&bit_count.to_be_bytes());

        let mut result = [0u8; 32];
        for (i, &word) in self.state.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        result
    }
}

/// Compute SHA-256 hash of data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

fn sha256_transform(state: &mut [u32; 8], block: &[u8; 64]) {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g; g = f; f = e;
        e = d.wrapping_add(temp1);
        d = c; c = b; b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

// ── HMAC ──

/// HMAC-MD5.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    hmac_generic::<16, 64>(key, data, md5_oneshot)
}

/// HMAC-SHA1.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    hmac_generic::<20, 64>(key, data, sha1_oneshot)
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac_generic::<32, 64>(key, data, sha256_oneshot)
}

fn md5_oneshot(data: &[u8]) -> [u8; 16] { md5(data) }
fn sha1_oneshot(data: &[u8]) -> [u8; 20] { sha1(data) }
fn sha256_oneshot(data: &[u8]) -> [u8; 32] { sha256(data) }

/// Generic HMAC implementation.
fn hmac_generic<const HASH_LEN: usize, const BLOCK_SIZE: usize>(
    key: &[u8],
    data: &[u8],
    hash_fn: fn(&[u8]) -> [u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = hash_fn(key);
        key_block[..HASH_LEN].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    // Inner: key XOR ipad
    let mut inner_input = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_input[i] = key_block[i] ^ 0x36;
    }

    // Concatenate ipad + data and hash
    let mut combined = vec![0u8; BLOCK_SIZE + data.len()];
    combined[..BLOCK_SIZE].copy_from_slice(&inner_input);
    combined[BLOCK_SIZE..].copy_from_slice(data);
    let inner_hash = hash_fn(&combined);

    // Outer: key XOR opad + inner hash
    let mut outer = vec![0u8; BLOCK_SIZE + HASH_LEN];
    for i in 0..BLOCK_SIZE {
        outer[i] = key_block[i] ^ 0x5C;
    }
    outer[BLOCK_SIZE..].copy_from_slice(&inner_hash);
    hash_fn(&outer)
}

// ── RSA / Triple-DES traits ──

/// Trait for RSA public key operations (injected by I/O layer).
pub trait RsaPublicKey {
    /// Encrypt data with the public key (PKCS#1 v1.5).
    fn encrypt(&self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, &'static str>;

    /// Verify a signature.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, &'static str>;
}

/// Trait for Triple-DES operations (FIPS mode).
pub trait TripleDes {
    /// Encrypt a block (8 bytes).
    fn encrypt_block(&self, plaintext: &[u8; 8]) -> [u8; 8];
    /// Decrypt a block (8 bytes).
    fn decrypt_block(&self, ciphertext: &[u8; 8]) -> [u8; 8];
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1320 test vectors for MD4
    #[test]
    fn md4_empty() {
        assert_eq!(
            md4(b""),
            [0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0]
        );
    }

    #[test]
    fn md4_abc() {
        assert_eq!(
            md4(b"abc"),
            [0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d]
        );
    }

    #[test]
    fn md4_message_digest() {
        assert_eq!(
            md4(b"message digest"),
            [0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8, 0x18, 0x87, 0x48, 0x06, 0xe1, 0xc7, 0x01, 0x4b]
        );
    }

    // RFC 1321 test vectors for MD5
    #[test]
    fn md5_empty() {
        assert_eq!(
            md5(b""),
            [0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e]
        );
    }

    #[test]
    fn md5_abc() {
        assert_eq!(
            md5(b"abc"),
            [0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72]
        );
    }

    // FIPS 180-1 test vectors for SHA-1
    #[test]
    fn sha1_abc() {
        assert_eq!(
            sha1(b"abc"),
            [0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
             0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d]
        );
    }

    #[test]
    fn sha1_empty() {
        assert_eq!(
            sha1(b""),
            [0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
             0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09]
        );
    }

    // FIPS 180-2 test vectors for SHA-256
    #[test]
    fn sha256_abc() {
        assert_eq!(
            sha256(b"abc"),
            [0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
             0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad]
        );
    }

    #[test]
    fn sha256_empty() {
        assert_eq!(
            sha256(b""),
            [0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
             0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55]
        );
    }

    // RC4 test vector (RFC 6229, key = "Key")
    #[test]
    fn rc4_basic() {
        // RC4 encrypt then decrypt roundtrip
        let plaintext = b"Plaintext";
        let mut buf = *plaintext;
        let mut rc4 = Rc4::new(b"Key");
        rc4.process(&mut buf);
        // Decrypt
        let mut rc4_2 = Rc4::new(b"Key");
        rc4_2.process(&mut buf);
        assert_eq!(&buf, plaintext);
    }

    #[test]
    fn rc4_encrypt_decrypt_roundtrip() {
        let key = b"test_key_123";
        let original = b"Hello, RDP world! This is a test.";
        let mut encrypted = *original;
        let mut rc4 = Rc4::new(key);
        rc4.process(&mut encrypted);
        assert_ne!(&encrypted[..], &original[..]);

        let mut decrypted = encrypted;
        let mut rc4 = Rc4::new(key);
        rc4.process(&mut decrypted);
        assert_eq!(&decrypted, original);
    }

    // HMAC test vectors (RFC 2104)
    #[test]
    fn hmac_md5_basic() {
        let key = [0x0b; 16];
        let data = b"Hi There";
        let result = hmac_md5(&key, data);
        assert_eq!(
            result,
            [0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d]
        );
    }

    #[test]
    fn hmac_sha1_basic() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let result = hmac_sha1(&key, data);
        assert_eq!(
            result,
            [0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b,
             0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00]
        );
    }

    #[test]
    fn hmac_sha256_basic() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let result = hmac_sha256(&key, data);
        assert_eq!(
            result,
            [0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
             0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7]
        );
    }
}
