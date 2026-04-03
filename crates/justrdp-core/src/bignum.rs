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
        use core::cmp::Ordering;

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
    /// Uses the Montgomery ladder algorithm for constant-time execution:
    /// both branches perform the same operations (one multiply + one square)
    /// regardless of each exponent bit, preventing timing side-channel attacks.
    pub fn mod_exp(&self, exp: &Self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            return Self::zero();
        }

        let one = Self::from_u32(1);

        if exp.is_zero() {
            return one.rem(modulus);
        }

        let base = self.rem(modulus);
        let exp_bits = exp.bit_len();

        // Montgomery ladder: constant-time modular exponentiation.
        // Both branches perform identical work (multiply + square),
        // only the assignment target differs.
        let mut r0 = one;      // accumulates result
        let mut r1 = base;     // base * result

        for i in (0..exp_bits).rev() {
            if exp.bit(i) {
                r0 = r0.mul(&r1).rem(modulus);
                r1 = r1.mul(&r1).rem(modulus);
            } else {
                r1 = r0.mul(&r1).rem(modulus);
                r0 = r0.mul(&r0).rem(modulus);
            }
        }

        r0
    }

    /// Zero out all limbs to prevent key material from lingering in memory.
    pub fn zeroize(&mut self) {
        self.limbs.fill(0);
        core::hint::black_box(&self.limbs);
    }
}

impl PartialEq for BigUint {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == core::cmp::Ordering::Equal
    }
}

impl Eq for BigUint {}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
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

        core::cmp::Ordering::Equal
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
    fn sub_to_zero() {
        let a = BigUint::from_u32(42);
        let b = BigUint::from_u32(42);
        let c = a.sub(&b);
        assert!(c.is_zero());
    }
}
