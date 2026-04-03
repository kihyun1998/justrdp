#![forbid(unsafe_code)]

//! Big unsigned integer arithmetic for DH/RSA.
//!
//! Provides a minimal `BigUint` implementation sufficient for:
//! - 2048-bit Diffie-Hellman key exchange
//! - RSA signing/verification (PKCS#1 v1.5)
//!
//! Uses base-2^32 limbs stored in little-endian order (least significant first).

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

/// Unsigned big integer, stored as little-endian base-2^32 limbs.
#[derive(Clone, Debug)]
pub struct BigUint {
    /// Limbs in little-endian order: limbs[0] is least significant.
    limbs: Vec<u32>,
}

impl BigUint {
    /// Zero value.
    pub fn zero() -> Self {
        Self { limbs: vec![0] }
    }

    /// Create from a single u32.
    pub fn from_u32(v: u32) -> Self {
        Self { limbs: vec![v] }
    }

    /// Create from big-endian bytes.
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        // Skip leading zeros
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        let bytes = &bytes[start..];

        if bytes.is_empty() {
            return Self::zero();
        }

        // Convert big-endian bytes to little-endian u32 limbs
        let n_limbs = (bytes.len() + 3) / 4;
        let mut limbs = vec![0u32; n_limbs];

        for (i, &b) in bytes.iter().rev().enumerate() {
            limbs[i / 4] |= (b as u32) << ((i % 4) * 8);
        }

        let mut r = Self { limbs };
        r.normalize();
        r
    }

    /// Convert to big-endian bytes.
    pub fn to_be_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut bytes = Vec::new();
        let mut started = false;

        for &limb in self.limbs.iter().rev() {
            for shift in (0..4).rev() {
                let b = (limb >> (shift * 8)) as u8;
                if !started && b == 0 {
                    continue;
                }
                started = true;
                bytes.push(b);
            }
        }

        if bytes.is_empty() {
            vec![0]
        } else {
            bytes
        }
    }

    /// Create from little-endian bytes.
    pub fn from_le_bytes(bytes: &[u8]) -> Self {
        // Strip trailing zeros
        let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
        let bytes = &bytes[..end];

        if bytes.is_empty() {
            return Self::zero();
        }

        let n_limbs = (bytes.len() + 3) / 4;
        let mut limbs = vec![0u32; n_limbs];

        for (i, &b) in bytes.iter().enumerate() {
            limbs[i / 4] |= (b as u32) << ((i % 4) * 8);
        }

        let mut r = Self { limbs };
        r.normalize();
        r
    }

    /// Convert to little-endian bytes.
    pub fn to_le_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut bytes = Vec::new();
        for &limb in &self.limbs {
            bytes.push(limb as u8);
            bytes.push((limb >> 8) as u8);
            bytes.push((limb >> 16) as u8);
            bytes.push((limb >> 24) as u8);
        }

        // Strip trailing zeros
        while bytes.len() > 1 && bytes.last() == Some(&0) {
            bytes.pop();
        }

        bytes
    }

    /// Convert to little-endian bytes, padded to `len` bytes.
    ///
    /// If the value requires more than `len` bytes, the high bytes are silently
    /// truncated. A debug_assert fires in debug builds if this happens.
    pub fn to_le_bytes_padded(&self, len: usize) -> Vec<u8> {
        let bytes = self.to_le_bytes();
        if bytes.len() >= len {
            debug_assert!(
                bytes[len..].iter().all(|&b| b == 0),
                "BigUint::to_le_bytes_padded: value exceeds {} bytes, high bytes truncated",
                len,
            );
            return bytes[..len].to_vec();
        }
        let mut padded = bytes;
        padded.resize(len, 0);
        padded
    }

    /// Convert to big-endian bytes, padded to `len` bytes.
    pub fn to_be_bytes_padded(&self, len: usize) -> Vec<u8> {
        let bytes = self.to_be_bytes();
        if bytes.len() >= len {
            // Take the last `len` bytes
            return bytes[bytes.len() - len..].to_vec();
        }
        let mut padded = vec![0u8; len - bytes.len()];
        padded.extend_from_slice(&bytes);
        padded
    }

    /// Check if zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    /// Number of significant bits.
    pub fn bit_len(&self) -> usize {
        for i in (0..self.limbs.len()).rev() {
            if self.limbs[i] != 0 {
                return i * 32 + (32 - self.limbs[i].leading_zeros() as usize);
            }
        }
        0
    }

    /// Get bit at position `pos` (0-indexed from LSB).
    fn bit(&self, pos: usize) -> bool {
        let limb_idx = pos / 32;
        let bit_idx = pos % 32;
        if limb_idx >= self.limbs.len() {
            return false;
        }
        (self.limbs[limb_idx] >> bit_idx) & 1 == 1
    }

    /// Remove trailing zero limbs (keeping at least one).
    fn normalize(&mut self) {
        while self.limbs.len() > 1 && self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    fn limb(&self, i: usize) -> u32 {
        if i < self.limbs.len() { self.limbs[i] } else { 0 }
    }

    fn significant_limbs(&self) -> usize {
        for i in (0..self.limbs.len()).rev() {
            if self.limbs[i] != 0 {
                return i + 1;
            }
        }
        1
    }

    /// self + other
    pub fn add(&self, other: &Self) -> Self {
        let n = core::cmp::max(self.limbs.len(), other.limbs.len());
        let mut result = vec![0u32; n + 1];
        let mut carry: u64 = 0;

        for i in 0..n {
            let sum = self.limb(i) as u64 + other.limb(i) as u64 + carry;
            result[i] = sum as u32;
            carry = sum >> 32;
        }
        result[n] = carry as u32;

        let mut r = Self { limbs: result };
        r.normalize();
        r
    }

    /// self - other (assumes self >= other).
    pub fn sub(&self, other: &Self) -> Self {
        let n = self.limbs.len();
        let mut result = vec![0u32; n];
        let mut borrow: i64 = 0;

        for i in 0..n {
            let diff = self.limb(i) as i64 - other.limb(i) as i64 - borrow;
            if diff < 0 {
                result[i] = (diff + (1i64 << 32)) as u32;
                borrow = 1;
            } else {
                result[i] = diff as u32;
                borrow = 0;
            }
        }

        let mut r = Self { limbs: result };
        r.normalize();
        r
    }

    /// self * other
    pub fn mul(&self, other: &Self) -> Self {
        let n = self.significant_limbs();
        let m = other.significant_limbs();
        let mut result = vec![0u32; n + m];

        for i in 0..n {
            let mut carry: u64 = 0;
            for j in 0..m {
                let prod = self.limbs[i] as u64 * other.limbs[j] as u64
                    + result[i + j] as u64
                    + carry;
                result[i + j] = prod as u32;
                carry = prod >> 32;
            }
            result[i + m] = carry as u32;
        }

        let mut r = Self { limbs: result };
        r.normalize();
        r
    }

    /// Division with remainder: returns (quotient, remainder).
    ///
    /// Uses binary long division. O(bit_len²) due to per-iteration allocation
    /// in `shl1`; acceptable for key-size operands (up to 2048-bit).
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        assert!(!divisor.is_zero(), "BigUint::div_rem: division by zero");

        match self.cmp(divisor) {
            Ordering::Less => return (Self::zero(), self.clone()),
            Ordering::Equal => return (Self::from_u32(1), Self::zero()),
            _ => {}
        }

        let n = self.bit_len();
        let mut quotient = vec![0u32; (n + 31) / 32];
        let mut remainder = Self::zero();

        for i in (0..n).rev() {
            // remainder = remainder << 1 | bit(i)
            remainder = remainder.shl1();
            if self.bit(i) {
                remainder.limbs[0] |= 1;
            }

            if remainder.cmp(divisor) != Ordering::Less {
                remainder = remainder.sub(divisor);
                quotient[i / 32] |= 1 << (i % 32);
            }
        }

        let mut q = Self { limbs: quotient };
        q.normalize();
        remainder.normalize();
        (q, remainder)
    }

    /// Shift left by 1 bit.
    fn shl1(&self) -> Self {
        let n = self.limbs.len();
        let mut result = vec![0u32; n + 1];
        let mut carry = 0u32;

        for i in 0..n {
            let shifted = ((self.limbs[i] as u64) << 1) | carry as u64;
            result[i] = shifted as u32;
            carry = (shifted >> 32) as u32;
        }
        result[n] = carry;

        let mut r = Self { limbs: result };
        r.normalize();
        r
    }

    /// self mod modulus
    pub fn rem(&self, modulus: &Self) -> Self {
        self.div_rem(modulus).1
    }

    /// Modular exponentiation: self^exp mod modulus.
    ///
    /// Uses Montgomery multiplication for the inner loop, ensuring all
    /// multiply/reduce operations run in fixed time proportional to the
    /// modulus width. The exponent bits are accessed via branchless
    /// conditional swap to prevent branch-prediction side-channels.
    ///
    /// Precomputation (Montgomery context setup) depends only on the modulus
    /// (public), not on the exponent (secret).
    pub fn mod_exp(&self, exp: &Self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            return Self::zero();
        }

        let one = Self::from_u32(1);

        if exp.is_zero() {
            return one.rem(modulus);
        }

        // Montgomery requires odd modulus. RSA moduli and DH primes are always odd.
        // For even modulus, fall back to non-Montgomery path.
        if modulus.limbs[0] & 1 == 0 {
            return self.mod_exp_basic(exp, modulus);
        }

        let base = self.rem(modulus);
        let exp_bits = exp.bit_len();
        let ctx = MontContext::new(modulus);
        let w = ctx.width;

        // Convert to Montgomery form: aR mod N
        let mut r0 = ctx.to_mont(&one);
        let mut r1 = ctx.to_mont(&base);

        // Binary exponentiation with constant-time conditional swap.
        // All mont_mul calls operate on fixed-width limb arrays.
        for i in (0..exp_bits).rev() {
            let bit = exp.bit(i);
            ct_swap_limbs(&mut r0, &mut r1, bit, w);
            r1 = ctx.mont_mul(&r0, &r1);
            r0 = ctx.mont_mul(&r0, &r0);
            ct_swap_limbs(&mut r0, &mut r1, bit, w);
        }

        // Convert back from Montgomery form
        let result_limbs = ctx.from_mont(&r0);
        let mut result = Self { limbs: result_limbs };
        result.normalize();
        result
    }

    /// Non-Montgomery fallback for even modulus (rare edge case).
    fn mod_exp_basic(&self, exp: &Self, modulus: &Self) -> Self {
        let one = Self::from_u32(1);
        let base = self.rem(modulus);
        let exp_bits = exp.bit_len();

        let mut r0 = one;
        let mut r1 = base;

        for i in (0..exp_bits).rev() {
            let bit = exp.bit(i);
            Self::ct_swap(&mut r0, &mut r1, bit);
            r1 = r0.mul(&r1).rem(modulus);
            r0 = r0.mul(&r0).rem(modulus);
            Self::ct_swap(&mut r0, &mut r1, bit);
        }
        r0
    }

    /// Branchless conditional swap on BigUint (used by mod_exp_basic fallback).
    fn ct_swap(a: &mut Self, b: &mut Self, condition: bool) {
        let max_len = core::cmp::max(a.limbs.len(), b.limbs.len());
        a.limbs.resize(max_len, 0);
        b.limbs.resize(max_len, 0);
        let mask = (condition as u32).wrapping_neg();
        for i in 0..max_len {
            let diff = a.limbs[i] ^ b.limbs[i];
            let masked = diff & mask;
            a.limbs[i] ^= masked;
            b.limbs[i] ^= masked;
        }
    }

    /// Zero out all limbs to prevent key material from lingering in memory.
    ///
    /// Uses `core::hint::black_box` as an optimization barrier. Note that this
    /// is a best-effort defense; LTO or aggressive optimizers may still elide
    /// the zeroing. For stronger guarantees, use the `zeroize` crate.
    pub fn zeroize(&mut self) {
        self.limbs.fill(0);
        core::hint::black_box(&self.limbs);
    }
}

// ── Constant-time helpers ──

/// Branchless conditional swap on fixed-width `Vec<u32>` limb arrays.
fn ct_swap_limbs(a: &mut Vec<u32>, b: &mut Vec<u32>, condition: bool, width: usize) {
    a.resize(width, 0);
    b.resize(width, 0);
    let mask = (condition as u32).wrapping_neg();
    for i in 0..width {
        let diff = a[i] ^ b[i];
        let masked = diff & mask;
        a[i] ^= masked;
        b[i] ^= masked;
    }
}

// ── Montgomery multiplication ──

/// Montgomery multiplication context for constant-time modular arithmetic.
///
/// Converts operands to Montgomery form (aR mod N) where R = 2^(32*width),
/// then performs multiplication without division. All operations iterate over
/// a fixed number of limbs, preventing timing side-channels.
struct MontContext {
    /// Modulus limbs, zero-padded to `width`.
    n: Vec<u32>,
    /// Fixed limb width (number of u32 words in the modulus).
    width: usize,
    /// Montgomery parameter: -N[0]^{-1} mod 2^32.
    n0_inv: u32,
    /// R^2 mod N — used to convert values into Montgomery form.
    r_squared: Vec<u32>,
}

impl MontContext {
    /// Create a Montgomery context for the given odd modulus.
    ///
    /// Precomputation depends only on the modulus (public), not on any secret.
    fn new(modulus: &BigUint) -> Self {
        let width = modulus.limbs.len();
        let mut n = modulus.limbs.clone();
        n.resize(width, 0);

        // Compute n0_inv = -N[0]^{-1} mod 2^32 via Newton's method.
        // Each iteration doubles the correct bits: 1 → 2 → 4 → 8 → 16 → 32.
        let n0 = n[0];
        let mut inv: u32 = 1;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u32.wrapping_sub(n0.wrapping_mul(inv)));
        }
        let n0_inv = inv.wrapping_neg();

        // Compute R^2 mod N where R = 2^(32*width).
        // Repeated doubling: only depends on modulus (public), non-ct is acceptable.
        let mut r_mod_n = BigUint::from_u32(1);
        for _ in 0..(32 * width) {
            r_mod_n = r_mod_n.shl1();
            if r_mod_n >= *modulus {
                r_mod_n = r_mod_n.sub(modulus);
            }
        }
        let r_sq = r_mod_n.mul(&r_mod_n).rem(modulus);
        let mut r_squared = r_sq.limbs;
        r_squared.resize(width, 0);

        Self { n, width, n0_inv, r_squared }
    }

    /// Montgomery multiplication: (a × b × R^{-1}) mod N.
    ///
    /// Both inputs must be in Montgomery form (width-padded limb arrays).
    /// Always performs width × width multiply + width reduction passes.
    fn mont_mul(&self, a: &[u32], b: &[u32]) -> Vec<u32> {
        let w = self.width;

        // Step 1: T = a × b (fixed-width schoolbook multiply)
        let mut t = vec![0u32; 2 * w + 2];
        for i in 0..w {
            let ai = a[i] as u64;
            let mut carry: u64 = 0;
            for j in 0..w {
                let sum = t[i + j] as u64 + ai * b[j] as u64 + carry;
                t[i + j] = sum as u32;
                carry = sum >> 32;
            }
            // Propagate carry (fixed iteration count: depends on i, not data)
            for k in (i + w)..(2 * w + 2) {
                let sum = t[k] as u64 + carry;
                t[k] = sum as u32;
                carry = sum >> 32;
            }
        }

        // Step 2: Montgomery reduction — add multiples of N to make T divisible by R
        for i in 0..w {
            let u = t[i].wrapping_mul(self.n0_inv) as u64;
            let mut carry: u64 = 0;
            for j in 0..w {
                let sum = t[i + j] as u64 + u * self.n[j] as u64 + carry;
                t[i + j] = sum as u32;
                carry = sum >> 32;
            }
            // Propagate carry (fixed iteration count)
            for k in (i + w)..(2 * w + 2) {
                let sum = t[k] as u64 + carry;
                t[k] = sum as u32;
                carry = sum >> 32;
            }
        }

        // Step 3: Result = T >> (32*width) — the upper half
        // The result can be up to 2N, fitting in w+1 limbs.
        let mut result = vec![0u32; w + 1];
        result[..w + 1].copy_from_slice(&t[w..2 * w + 1]);

        // Step 4: Constant-time conditional subtraction (if result >= N, subtract N)
        let mut borrow: u64 = 0;
        let mut diff = vec![0u32; w + 1];
        for k in 0..=w {
            let nk = if k < w { self.n[k] } else { 0 };
            let sub = (result[k] as u64).wrapping_sub(nk as u64).wrapping_sub(borrow);
            diff[k] = sub as u32;
            borrow = (sub >> 32) & 1;
        }
        // mask = 0xFFFFFFFF if no borrow (result >= N), 0 otherwise
        let mask = (borrow as u32).wrapping_sub(1);
        for k in 0..w {
            result[k] = (diff[k] & mask) | (result[k] & !mask);
        }

        result.truncate(w);
        result
    }

    /// Convert to Montgomery form: aR mod N.
    fn to_mont(&self, a: &BigUint) -> Vec<u32> {
        let mut a_padded = a.limbs.clone();
        a_padded.resize(self.width, 0);
        self.mont_mul(&a_padded, &self.r_squared)
    }

    /// Convert from Montgomery form: a × R^{-1} mod N.
    fn from_mont(&self, a_mont: &[u32]) -> Vec<u32> {
        let mut one = vec![0u32; self.width];
        one[0] = 1;
        self.mont_mul(a_mont, &one)
    }
}

impl PartialEq for BigUint {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for BigUint {}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        let a_len = self.significant_limbs();
        let b_len = other.significant_limbs();

        if a_len != b_len {
            return a_len.cmp(&b_len);
        }

        for i in (0..a_len).rev() {
            let a = self.limb(i);
            let b = other.limb(i);
            if a != b {
                return a.cmp(&b);
            }
        }

        Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_be_bytes_roundtrip() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05];
        let n = BigUint::from_be_bytes(&bytes);
        let out = n.to_be_bytes();
        assert_eq!(out, bytes);
    }

    #[test]
    fn zero() {
        let z = BigUint::zero();
        assert!(z.is_zero());
        assert_eq!(z.to_be_bytes(), vec![0]);
    }

    #[test]
    fn add_basic() {
        let a = BigUint::from_be_bytes(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let b = BigUint::from_u32(1);
        let c = a.add(&b);
        assert_eq!(c.to_be_bytes(), vec![0x01, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn sub_basic() {
        let a = BigUint::from_be_bytes(&[0x01, 0x00, 0x00, 0x00, 0x00]);
        let b = BigUint::from_u32(1);
        let c = a.sub(&b);
        assert_eq!(c.to_be_bytes(), vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn mul_basic() {
        let a = BigUint::from_u32(12345);
        let b = BigUint::from_u32(67890);
        let c = a.mul(&b);
        // 12345 * 67890 = 838102050
        assert_eq!(c.to_be_bytes(), 838102050u32.to_be_bytes().to_vec());
    }

    #[test]
    fn div_rem_basic() {
        let a = BigUint::from_u32(100);
        let b = BigUint::from_u32(7);
        let (q, r) = a.div_rem(&b);
        // 100 / 7 = 14 remainder 2
        assert_eq!(q, BigUint::from_u32(14));
        assert_eq!(r, BigUint::from_u32(2));
    }

    #[test]
    fn mod_exp_small() {
        // 2^10 mod 1000 = 1024 mod 1000 = 24
        let base = BigUint::from_u32(2);
        let exp = BigUint::from_u32(10);
        let modulus = BigUint::from_u32(1000);
        let result = base.mod_exp(&exp, &modulus);
        assert_eq!(result, BigUint::from_u32(24));
    }

    #[test]
    fn mod_exp_medium() {
        // 3^13 mod 100 = 1594323 mod 100 = 23
        let base = BigUint::from_u32(3);
        let exp = BigUint::from_u32(13);
        let modulus = BigUint::from_u32(100);
        let result = base.mod_exp(&exp, &modulus);
        assert_eq!(result, BigUint::from_u32(23));
    }

    #[test]
    fn mod_exp_fermat() {
        // Fermat's little theorem: a^(p-1) ≡ 1 (mod p) for prime p
        // 2^6 mod 7 = 64 mod 7 = 1
        let base = BigUint::from_u32(2);
        let exp = BigUint::from_u32(6);
        let modulus = BigUint::from_u32(7);
        let result = base.mod_exp(&exp, &modulus);
        assert_eq!(result, BigUint::from_u32(1));
    }

    #[test]
    fn to_be_bytes_padded() {
        let n = BigUint::from_u32(0xFF);
        let padded = n.to_be_bytes_padded(4);
        assert_eq!(padded, vec![0, 0, 0, 0xFF]);
    }

    #[test]
    fn compare() {
        let a = BigUint::from_u32(100);
        let b = BigUint::from_u32(200);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, BigUint::from_u32(100));
    }

    #[test]
    fn large_number_roundtrip() {
        // 256-bit number
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        let n = BigUint::from_be_bytes(&bytes);
        assert_eq!(n.to_be_bytes(), bytes.to_vec());
    }

    #[test]
    fn bit_len() {
        assert_eq!(BigUint::from_u32(0).bit_len(), 0);
        assert_eq!(BigUint::from_u32(1).bit_len(), 1);
        assert_eq!(BigUint::from_u32(255).bit_len(), 8);
        assert_eq!(BigUint::from_u32(256).bit_len(), 9);
    }

    #[test]
    fn from_le_bytes_roundtrip() {
        let bytes = [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        let n = BigUint::from_le_bytes(&bytes);
        let out = n.to_le_bytes();
        assert_eq!(out, bytes);
    }

    #[test]
    fn le_be_consistency() {
        // Same number in LE and BE
        let le = [0x01, 0x02, 0x03, 0x04]; // 0x04030201
        let be = [0x04, 0x03, 0x02, 0x01]; // 0x04030201
        let n_le = BigUint::from_le_bytes(&le);
        let n_be = BigUint::from_be_bytes(&be);
        assert_eq!(n_le, n_be);
    }

    #[test]
    fn mod_exp_boundary_exponents() {
        let base = BigUint::from_u32(7);
        let m = BigUint::from_u32(13);
        // x^0 mod m = 1
        assert_eq!(base.mod_exp(&BigUint::from_u32(0), &m), BigUint::from_u32(1));
        // x^1 mod m = x mod m
        assert_eq!(base.mod_exp(&BigUint::from_u32(1), &m), BigUint::from_u32(7));
    }

    #[test]
    fn mont_vs_basic_mod_exp() {
        // Test that Montgomery mod_exp matches basic mod_exp for a large prime
        let p = BigUint::from_be_bytes(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x43, // A large prime
        ]);
        let base = BigUint::from_u32(12345);
        let exp = BigUint::from_u32(67890);

        let mont_result = base.mod_exp(&exp, &p);
        let basic_result = base.mod_exp_basic(&exp, &p);
        assert_eq!(mont_result, basic_result, "Montgomery and basic mod_exp disagree");
    }

    #[test]
    fn sub_to_zero() {
        let a = BigUint::from_u32(42);
        let b = BigUint::from_u32(42);
        let c = a.sub(&b);
        assert!(c.is_zero());
    }
}
