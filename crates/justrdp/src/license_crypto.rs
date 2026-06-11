//! The legacy cryptography MS-RDPELE licensing mandates: MD5/SHA-1 key derivation, RC4 message
//! encryption, and raw (textbook) RSA for the premaster secret. Hand-rolled because plan.md
//! decision 6 keeps the RDP-protocol crates dependency-free, and ADR-0002 reserves external
//! crypto dependencies for the *security-critical* layers (TLS/NLA) — which licensing is not:
//! it rides **inside** the already-authenticated TLS session, and its algorithms are frozen by
//! the spec (MS-RDPELE 5.1).
//!
//! **Not general-purpose cryptography.** MD5/SHA-1/RC4/unpadded RSA are broken primitives by
//! modern standards; they exist here solely because the licensing wire format requires them.
//! Nothing outside the licensing exchange may use this module.

/// One MD5 digest (RFC 1321). Used by the licensing key derivation and MAC.
pub fn md5(data: &[u8]) -> [u8; 16] {
    // Per-round left-rotate amounts.
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    // K[i] = floor(2^32 * |sin(i + 1)|).
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);

    for block in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// One SHA-1 digest (RFC 3174). Used by the licensing key derivation and MAC.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// RC4-encrypt (or decrypt — the cipher is symmetric) `data` with `key`. Each licensing
/// message uses a fresh keystream (MS-RDPELE resets the cipher per message).
pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    data.iter()
        .map(|&byte| {
            i = (i + 1) % 256;
            j = (j + s[i] as usize) % 256;
            s.swap(i, j);
            byte ^ s[(s[i] as usize + s[j] as usize) % 256]
        })
        .collect()
}

/// `SaltedHash` (MS-RDPELE 5.1.3): `MD5(salt ‖ SHA1(input ‖ salt ‖ salt1 ‖ salt2))`.
fn salted_hash(salt: &[u8], salt1: &[u8], salt2: &[u8], input: &[u8]) -> [u8; 16] {
    let sha = sha1(&[input, salt, salt1, salt2].concat());
    md5(&[salt, &sha].concat())
}

/// The licensing session keys derived from the three randoms (MS-RDPELE 5.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseKeys {
    /// The RC4 key for `EncryptedPlatformChallenge` / responses / license info.
    pub license_key: [u8; 16],
    /// The MAC salt for [`mac_data`].
    pub mac_salt: [u8; 16],
}

/// Derive [`LicenseKeys`] from the premaster secret and both randoms (MS-RDPELE 5.1.3):
/// MasterSecret = SaltedHash(premaster, client, server; "A"/"BB"/"CCC"), SessionKeyBlob =
/// SaltedHash(master, server, client; "A"/"BB"/"CCC"), MAC salt = blob[0..16], license key =
/// `MD5(blob[16..32] ‖ client ‖ server)`.
pub fn derive_license_keys(
    premaster_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> LicenseKeys {
    let master_secret: Vec<u8> = [&b"A"[..], b"BB", b"CCC"]
        .iter()
        .flat_map(|label| salted_hash(premaster_secret, client_random, server_random, label))
        .collect();
    let session_key_blob: Vec<u8> = [&b"A"[..], b"BB", b"CCC"]
        .iter()
        .flat_map(|label| salted_hash(&master_secret, server_random, client_random, label))
        .collect();

    let mut mac_salt = [0u8; 16];
    mac_salt.copy_from_slice(&session_key_blob[0..16]);
    let license_key = md5(&[&session_key_blob[16..32], client_random, server_random].concat());
    LicenseKeys {
        license_key,
        mac_salt,
    }
}

/// The licensing MAC (MS-RDPELE 5.1.6): `MD5(salt ‖ pad2 ‖ SHA1(salt ‖ pad1 ‖ len_LE ‖ data))`
/// with `pad1` = 40×0x36 and `pad2` = 48×0x5C. Computed over **plaintext**, sent alongside the
/// RC4-encrypted copy.
pub fn mac_data(mac_salt: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let pad1 = [0x36u8; 40];
    let pad2 = [0x5Cu8; 48];
    let len = (data.len() as u32).to_le_bytes();
    let sha = sha1(&[&mac_salt[..], &pad1, &len, data].concat());
    md5(&[&mac_salt[..], &pad2, &sha].concat())
}

/// Textbook RSA for the premaster secret (MS-RDPELE 5.1.2.1): interpret the secret as a
/// little-endian integer, raise to the certificate's public exponent mod its modulus, and emit
/// the result little-endian with 8 trailing zero bytes (the proprietary blob convention,
/// matching FreeRDP). `modulus_be` is **big-endian** — [`crate::connect`] reverses the wire's
/// little-endian modulus when parsing the certificate, per MS-RDPBCGR 2.2.1.4.3.1.1.1. (Do not
/// oracle this against ironrdp 0.8: it skips that reversal, so its full-path licensing RSA is
/// spec-incorrect — see the differential test notes.)
pub fn encrypt_premaster_secret(
    premaster_secret: &[u8],
    modulus_be: &[u8],
    exponent: u32,
) -> Vec<u8> {
    let m = BigUint::from_bytes_le(premaster_secret);
    let n = BigUint::from_bytes_be(modulus_be);
    let c = m.modpow(exponent, &n);
    let mut out = c.to_bytes_le();
    out.resize(out.len() + 8, 0);
    out
}

/// A minimal unsigned big integer — just enough for one RSA public-key operation per connect.
/// Little-endian `u32` limbs; schoolbook multiply and binary (shift-subtract) reduction:
/// O(n²) words, microseconds at 2048 bits, zero dependencies.
struct BigUint {
    /// Little-endian limbs, no trailing zeros.
    limbs: Vec<u32>,
}

impl BigUint {
    fn trim(mut limbs: Vec<u32>) -> Self {
        while limbs.last() == Some(&0) {
            limbs.pop();
        }
        Self { limbs }
    }

    fn from_bytes_le(bytes: &[u8]) -> Self {
        let limbs = bytes
            .chunks(4)
            .map(|c| {
                let mut buf = [0u8; 4];
                buf[..c.len()].copy_from_slice(c);
                u32::from_le_bytes(buf)
            })
            .collect();
        Self::trim(limbs)
    }

    fn from_bytes_be(bytes: &[u8]) -> Self {
        let mut le = bytes.to_vec();
        le.reverse();
        Self::from_bytes_le(&le)
    }

    /// Little-endian bytes, minimal length (no high-order zeros) — matching
    /// `num_bigint::BigUint::to_bytes_le`, which the differential oracle uses.
    fn to_bytes_le(&self) -> Vec<u8> {
        let mut out: Vec<u8> = self.limbs.iter().flat_map(|l| l.to_le_bytes()).collect();
        while out.last() == Some(&0) {
            out.pop();
        }
        if out.is_empty() {
            out.push(0);
        }
        out
    }

    fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    fn bits(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(top) => self.limbs.len() * 32 - top.leading_zeros() as usize,
        }
    }

    fn bit(&self, i: usize) -> bool {
        self.limbs
            .get(i / 32)
            .is_some_and(|l| l >> (i % 32) & 1 == 1)
    }

    fn ge(&self, other: &Self) -> bool {
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len() > other.limbs.len();
        }
        for (a, b) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            if a != b {
                return a > b;
            }
        }
        true
    }

    /// `self -= other`; caller guarantees `self >= other`.
    fn sub_assign(&mut self, other: &Self) {
        let mut borrow = 0i64;
        for i in 0..self.limbs.len() {
            let rhs = *other.limbs.get(i).unwrap_or(&0) as i64;
            let mut v = self.limbs[i] as i64 - rhs - borrow;
            borrow = 0;
            if v < 0 {
                v += 1 << 32;
                borrow = 1;
            }
            self.limbs[i] = v as u32;
        }
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    /// `self << bits` (whole value).
    fn shl(&self, bits: usize) -> Self {
        if self.is_zero() {
            return Self { limbs: Vec::new() };
        }
        let (words, rem) = (bits / 32, bits % 32);
        let mut limbs = vec![0u32; words];
        let mut carry = 0u32;
        for &l in &self.limbs {
            if rem == 0 {
                limbs.push(l);
            } else {
                limbs.push((l << rem) | carry);
                carry = l >> (32 - rem);
            }
        }
        if rem != 0 && carry != 0 {
            limbs.push(carry);
        }
        Self::trim(limbs)
    }

    /// Schoolbook multiplication.
    fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self { limbs: Vec::new() };
        }
        let mut acc = vec![0u64; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.limbs.iter().enumerate() {
                let v = acc[i + j] + a as u64 * b as u64 + carry;
                acc[i + j] = v & 0xFFFF_FFFF;
                carry = v >> 32;
            }
            // Propagate the final carry so every slot stays below 2^32 — the inner loop's
            // u64 accumulation overflows otherwise.
            let mut k = i + other.limbs.len();
            while carry > 0 {
                let v = acc[k] + carry;
                acc[k] = v & 0xFFFF_FFFF;
                carry = v >> 32;
                k += 1;
            }
        }
        Self::trim(acc.into_iter().map(|v| v as u32).collect())
    }

    /// `self mod m` by binary shift-subtract.
    fn rem(mut self, m: &Self) -> Self {
        if !self.ge(m) {
            return self;
        }
        let shift = self.bits() - m.bits();
        for s in (0..=shift).rev() {
            let d = m.shl(s);
            if self.ge(&d) {
                self.sub_assign(&d);
            }
        }
        self
    }

    /// `self^exponent mod m` by square-and-multiply over the exponent's bits.
    fn modpow(&self, exponent: u32, m: &Self) -> Self {
        let exp = Self::from_bytes_le(&exponent.to_le_bytes());
        let mut result = Self { limbs: vec![1] };
        let mut base = Self {
            limbs: self.limbs.clone(),
        }
        .rem(m);
        for i in 0..exp.bits() {
            if exp.bit(i) {
                result = result.mul(&base).rem(m);
            }
            base = base.mul(&base).rem(m);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn md5_known_vectors() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        // Two-block input (> 64 bytes) exercises the chaining.
        assert_eq!(
            hex(&md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn sha1_known_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn rc4_known_vectors() {
        assert_eq!(hex(&rc4(b"Key", b"Plaintext")), "bbf316e8d940af0ad3");
        assert_eq!(hex(&rc4(b"Wiki", b"pedia")), "1021bf0420");
        // Symmetry: encrypting twice round-trips.
        let cipher = rc4(b"Secret", b"Attack at dawn");
        assert_eq!(rc4(b"Secret", &cipher), b"Attack at dawn");
    }

    #[test]
    fn modpow_small_numbers() {
        // 4^13 mod 497 = 445 (classic textbook example).
        let base = BigUint::from_bytes_le(&[4]);
        let m = BigUint::from_bytes_le(&497u32.to_le_bytes());
        assert_eq!(base.modpow(13, &m).to_bytes_le(), 445u16.to_le_bytes());
        // Exponent 65537 against a 64-bit modulus, verified with an independent
        // computation (python pow): pow(0xDEADBEEF, 65537, 0xC353118439A75501) =
        // 0x541CCB973FAAFF12.
        let base = BigUint::from_bytes_be(&0xDEAD_BEEFu32.to_be_bytes());
        let m = BigUint::from_bytes_be(&0xC353_1184_39A7_5501u64.to_be_bytes());
        let mut expected = 0x541C_CB97_3FAA_FF12u64.to_le_bytes().to_vec();
        while expected.last() == Some(&0) {
            expected.pop();
        }
        assert_eq!(base.modpow(65537, &m).to_bytes_le(), expected);
    }

    #[test]
    fn encrypted_premaster_carries_proprietary_padding() {
        let out = encrypt_premaster_secret(&[0x42; 48], &[0xC3; 64], 65537);
        // Result is at most modulus-sized, plus exactly 8 trailing zero bytes.
        assert!(out.len() <= 64 + 8);
        assert_eq!(&out[out.len() - 8..], &[0; 8]);
    }

    #[test]
    fn derive_license_keys_is_deterministic_and_salt_order_sensitive() {
        let keys = derive_license_keys(&[1; 48], &[2; 32], &[3; 32]);
        let again = derive_license_keys(&[1; 48], &[2; 32], &[3; 32]);
        assert_eq!(keys, again);
        // Swapping the randoms must change the keys (the derivation salts differ by order).
        let swapped = derive_license_keys(&[1; 48], &[3; 32], &[2; 32]);
        assert_ne!(keys, swapped);
    }

    #[test]
    fn mac_data_changes_with_content_and_salt() {
        let salt = [7u8; 16];
        let mac = mac_data(&salt, b"hello");
        assert_ne!(mac, mac_data(&salt, b"hellp"));
        assert_ne!(mac, mac_data(&[8u8; 16], b"hello"));
    }
}
