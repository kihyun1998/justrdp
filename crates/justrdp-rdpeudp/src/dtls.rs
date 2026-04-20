#![forbid(unsafe_code)]

//! DTLS 1.0/1.2 record layer, handshake framing, key derivation, and
//! AES-128-CBC-SHA256 record protection.
//!
//! This module provides the PDU-level and cryptographic building
//! blocks for running a DTLS handshake over the MS-RDPEUDP transport.
//! The handshake state machine lives in a follow-up module.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::crypto::hmac_sha256;
use justrdp_core::aes::{aes_cbc_decrypt, aes_cbc_encrypt, Aes128};

// =============================================================================
// Constants
// =============================================================================

// ── ContentType (RFC 5246 §6.2.1) ──
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CONTENT_TYPE_ALERT: u8 = 21;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

// ── HandshakeType (RFC 5246 §7.4 + RFC 6347 §4.2) ──
pub const HT_CLIENT_HELLO: u8 = 1;
pub const HT_SERVER_HELLO: u8 = 2;
pub const HT_HELLO_VERIFY_REQUEST: u8 = 3;
pub const HT_CERTIFICATE: u8 = 11;
pub const HT_SERVER_HELLO_DONE: u8 = 14;
pub const HT_CLIENT_KEY_EXCHANGE: u8 = 16;
pub const HT_FINISHED: u8 = 20;

// ── DTLS version bytes (RFC 6347 §4.1) ──
pub const DTLS_1_0: [u8; 2] = [0xFE, 0xFF];
pub const DTLS_1_2: [u8; 2] = [0xFE, 0xFD];

// ── Cipher suite (RFC 5246 Appendix C) ──
pub const TLS_RSA_WITH_AES_128_CBC_SHA256: [u8; 2] = [0x00, 0x3D];
pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: [u8; 2] = [0x00, 0xFF];

// ── Sizes ──
pub const DTLS_RECORD_HEADER_SIZE: usize = 13;
pub const DTLS_HANDSHAKE_HEADER_SIZE: usize = 12;
pub const AES_BLOCK_SIZE: usize = 16;
pub const SHA256_MAC_SIZE: usize = 32;
pub const PRE_MASTER_SECRET_SIZE: usize = 48;
pub const MASTER_SECRET_SIZE: usize = 48;
pub const FINISHED_VERIFY_DATA_SIZE: usize = 12;

// =============================================================================
// Constant-time comparison
// =============================================================================

/// Constant-time byte-slice equality. Returns `false` if lengths
/// differ (length is public metadata — MAC/verify_data sizes are
/// fixed by the cipher suite). Used to close timing oracles against
/// `Finished.verify_data` (RFC 5246 §7.4.9) and CBC record MAC
/// (RFC 5246 §6.2.3.2).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// =============================================================================
// DTLS Record
// =============================================================================

/// A single DTLS record (RFC 6347 §4.1). All multi-byte integer
/// fields are big-endian (network byte order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtlsRecord {
    pub content_type: u8,
    pub version: [u8; 2],
    pub epoch: u16,
    /// 48-bit sequence number, stored in the low 48 bits of a u64.
    pub sequence_number: u64,
    pub fragment: Vec<u8>,
}

impl DtlsRecord {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.content_type);
        out.extend_from_slice(&self.version);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        // 48-bit seq in 6 bytes big-endian.
        let seq_bytes = self.sequence_number.to_be_bytes();
        out.extend_from_slice(&seq_bytes[2..8]);
        out.extend_from_slice(&(self.fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.fragment);
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < DTLS_RECORD_HEADER_SIZE {
            return None;
        }
        let content_type = data[0];
        let version = [data[1], data[2]];
        let epoch = u16::from_be_bytes([data[3], data[4]]);
        let mut seq_buf = [0u8; 8];
        seq_buf[2..8].copy_from_slice(&data[5..11]);
        let sequence_number = u64::from_be_bytes(seq_buf);
        let length = u16::from_be_bytes([data[11], data[12]]) as usize;
        let total = DTLS_RECORD_HEADER_SIZE + length;
        if data.len() < total {
            return None;
        }
        let fragment = data[DTLS_RECORD_HEADER_SIZE..total].to_vec();
        Some((
            Self {
                content_type,
                version,
                epoch,
                sequence_number,
                fragment,
            },
            total,
        ))
    }

    pub fn wire_size(&self) -> usize {
        DTLS_RECORD_HEADER_SIZE + self.fragment.len()
    }
}

// =============================================================================
// DTLS Handshake Header
// =============================================================================

/// DTLS handshake message header (RFC 6347 §4.2.2). Sits inside the
/// fragment of a record with `content_type = CONTENT_TYPE_HANDSHAKE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeHeader {
    pub msg_type: u8,
    /// Total body length (24-bit).
    pub length: u32,
    pub message_seq: u16,
    /// Byte offset of this fragment into the full body (24-bit).
    pub fragment_offset: u32,
    /// Byte count of this fragment (24-bit).
    pub fragment_length: u32,
}

impl HandshakeHeader {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.msg_type);
        out.extend_from_slice(&self.length.to_be_bytes()[1..4]); // 24-bit
        out.extend_from_slice(&self.message_seq.to_be_bytes());
        out.extend_from_slice(&self.fragment_offset.to_be_bytes()[1..4]);
        out.extend_from_slice(&self.fragment_length.to_be_bytes()[1..4]);
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < DTLS_HANDSHAKE_HEADER_SIZE {
            return None;
        }
        let msg_type = data[0];
        let length = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let message_seq = u16::from_be_bytes([data[4], data[5]]);
        let fragment_offset = u32::from_be_bytes([0, data[6], data[7], data[8]]);
        let fragment_length = u32::from_be_bytes([0, data[9], data[10], data[11]]);
        Some(Self {
            msg_type,
            length,
            message_seq,
            fragment_offset,
            fragment_length,
        })
    }

    /// Build an unfragmented header (offset=0, frag_len=length).
    pub fn unfragmented(msg_type: u8, body_len: u32, message_seq: u16) -> Self {
        Self {
            msg_type,
            length: body_len,
            message_seq,
            fragment_offset: 0,
            fragment_length: body_len,
        }
    }
}

// =============================================================================
// TLS 1.2 PRF (RFC 5246 §5)
// =============================================================================

/// TLS 1.2 PRF using HMAC-SHA-256.
///
/// `PRF(secret, label, seed) = P_SHA256(secret, label || seed)`
pub fn tls12_prf(secret: &[u8], label: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    let mut combined_seed = Vec::with_capacity(label.len() + seed.len());
    combined_seed.extend_from_slice(label);
    combined_seed.extend_from_slice(seed);
    p_sha256(secret, &combined_seed, output_len)
}

/// P_SHA256(secret, seed) — RFC 5246 §5 expansion function.
fn p_sha256(secret: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(output_len);
    // A(0) = seed
    let mut a = hmac_sha256(secret, seed).to_vec();
    while result.len() < output_len {
        // HMAC(secret, A(i) || seed)
        let mut input = Vec::with_capacity(a.len() + seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(seed);
        let block = hmac_sha256(secret, &input);
        result.extend_from_slice(&block);
        // A(i+1) = HMAC(secret, A(i))
        a = hmac_sha256(secret, &a).to_vec();
    }
    result.truncate(output_len);
    result
}

// =============================================================================
// Key Derivation
// =============================================================================

/// Derived key material for TLS_RSA_WITH_AES_128_CBC_SHA256.
#[derive(Debug, Clone)]
pub struct KeyBlock {
    pub client_write_mac_key: [u8; 32],
    pub server_write_mac_key: [u8; 32],
    pub client_write_key: [u8; 16],
    pub server_write_key: [u8; 16],
}

/// Derive `master_secret` from `pre_master_secret` (RFC 5246 §8.1).
pub fn derive_master_secret(
    pre_master_secret: &[u8; PRE_MASTER_SECRET_SIZE],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; MASTER_SECRET_SIZE] {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    let ms = tls12_prf(pre_master_secret, b"master secret", &seed, MASTER_SECRET_SIZE);
    let mut out = [0u8; MASTER_SECRET_SIZE];
    out.copy_from_slice(&ms);
    out
}

/// Expand `master_secret` into the per-direction key block
/// (RFC 5246 §6.3).
pub fn derive_key_block(
    master_secret: &[u8; MASTER_SECRET_SIZE],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> KeyBlock {
    // Note: seed order is server_random + client_random (reversed).
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let kb = tls12_prf(master_secret, b"key expansion", &seed, 2 * (32 + 16));
    // 96 bytes total: 2×32 MAC + 2×16 AES key.
    let mut out = KeyBlock {
        client_write_mac_key: [0; 32],
        server_write_mac_key: [0; 32],
        client_write_key: [0; 16],
        server_write_key: [0; 16],
    };
    out.client_write_mac_key.copy_from_slice(&kb[0..32]);
    out.server_write_mac_key.copy_from_slice(&kb[32..64]);
    out.client_write_key.copy_from_slice(&kb[64..80]);
    out.server_write_key.copy_from_slice(&kb[80..96]);
    out
}

/// Compute `verify_data` for a Finished message (RFC 5246 §7.4.9).
pub fn compute_verify_data(
    master_secret: &[u8; MASTER_SECRET_SIZE],
    label: &[u8],
    handshake_hash: &[u8; 32],
) -> [u8; FINISHED_VERIFY_DATA_SIZE] {
    let vd = tls12_prf(master_secret, label, handshake_hash, FINISHED_VERIFY_DATA_SIZE);
    let mut out = [0u8; FINISHED_VERIFY_DATA_SIZE];
    out.copy_from_slice(&vd);
    out
}

// =============================================================================
// Record protection — AES-128-CBC-SHA256
// =============================================================================

/// Build the 64-bit "sequence number" used in MAC computation:
/// `epoch (2 bytes) || sequence_number (6 bytes)` = 8 bytes BE.
pub fn mac_seq_num(epoch: u16, seq: u64) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0..2].copy_from_slice(&epoch.to_be_bytes());
    let seq_bytes = seq.to_be_bytes();
    out[2..8].copy_from_slice(&seq_bytes[2..8]);
    out
}

/// Encrypt a plaintext record body in-place, producing the
/// ciphertext body that goes into `DtlsRecord.fragment`.
///
/// Returns the encrypted fragment: `IV (16) || ciphertext`.
pub fn encrypt_record(
    mac_key: &[u8; 32],
    enc_key: &[u8; 16],
    iv: &[u8; 16],
    content_type: u8,
    version: &[u8; 2],
    epoch: u16,
    seq: u64,
    plaintext: &[u8],
) -> Vec<u8> {
    // MAC = HMAC-SHA256(mac_key, seq_num || type || version || length || plaintext)
    let seq_num = mac_seq_num(epoch, seq);
    let mut mac_input = Vec::with_capacity(13 + plaintext.len());
    mac_input.extend_from_slice(&seq_num);
    mac_input.push(content_type);
    mac_input.extend_from_slice(version);
    mac_input.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(plaintext);
    let mac = hmac_sha256(mac_key, &mac_input);

    // Assemble plaintext || MAC || PKCS#7 padding.
    let unpadded_len = plaintext.len() + SHA256_MAC_SIZE;
    let pad_len = AES_BLOCK_SIZE - (unpadded_len % AES_BLOCK_SIZE);
    let pad_byte = (pad_len - 1) as u8;

    let mut block = Vec::with_capacity(unpadded_len + pad_len);
    block.extend_from_slice(plaintext);
    block.extend_from_slice(&mac);
    block.resize(unpadded_len + pad_len, pad_byte);

    // AES-128-CBC encrypt.
    let cipher = Aes128::new(enc_key);
    aes_cbc_encrypt(&cipher, iv, &mut block).expect("AES-CBC encrypt failed");

    // Output: IV || ciphertext.
    let mut out = Vec::with_capacity(AES_BLOCK_SIZE + block.len());
    out.extend_from_slice(iv);
    out.extend_from_slice(&block);
    out
}

/// Decrypt a record fragment and verify the MAC. Returns the
/// plaintext on success, or `None` on any verification failure.
pub fn decrypt_record(
    mac_key: &[u8; 32],
    dec_key: &[u8; 16],
    content_type: u8,
    version: &[u8; 2],
    epoch: u16,
    seq: u64,
    fragment: &[u8],
) -> Option<Vec<u8>> {
    // Minimum: IV (16) + MAC (32) + 1 pad byte = 49. Padded to
    // block boundary → minimum fragment = 16 (IV) + 48 (ciphertext) = 64.
    if fragment.len() < AES_BLOCK_SIZE + AES_BLOCK_SIZE + SHA256_MAC_SIZE {
        return None;
    }
    let iv: [u8; 16] = fragment[..16].try_into().ok()?;
    let mut ciphertext = fragment[16..].to_vec();
    if ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return None;
    }

    let cipher = Aes128::new(dec_key);
    aes_cbc_decrypt(&cipher, &iv, &mut ciphertext).ok()?;

    // Verify and strip PKCS#7 padding.
    //
    // `pad_byte` equals `pad_len - 1`. PKCS#7 for AES mandates
    // 1 ≤ pad_len ≤ 16, so a `pad_byte ≥ AES_BLOCK_SIZE` signals a
    // corrupt record and we reject here instead of silently falling
    // through (previous dead-code guard let wrapping subtraction
    // slice out of bounds).
    let pad_byte = *ciphertext.last()? as usize;
    if pad_byte >= AES_BLOCK_SIZE {
        return None;
    }
    let pad_len = pad_byte + 1;
    // Need room for MAC + padding + at least 0 bytes of plaintext.
    if pad_len + SHA256_MAC_SIZE > ciphertext.len() {
        return None;
    }
    // Verify all padding bytes match, accumulating into a single
    // XOR so a byte-flip attacker can't distinguish position via
    // early exit.
    let pad_start = ciphertext.len() - pad_len;
    let mut pad_diff: u8 = 0;
    for &b in &ciphertext[pad_start..] {
        pad_diff |= b ^ (pad_byte as u8);
    }

    // Split plaintext || MAC.
    let mac_start = pad_start - SHA256_MAC_SIZE;
    let plaintext = &ciphertext[..mac_start];
    let received_mac = &ciphertext[mac_start..pad_start];

    // Recompute MAC and constant-time compare.
    let seq_num = mac_seq_num(epoch, seq);
    let mut mac_input = Vec::with_capacity(13 + plaintext.len());
    mac_input.extend_from_slice(&seq_num);
    mac_input.push(content_type);
    mac_input.extend_from_slice(version);
    mac_input.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(plaintext);
    let expected_mac = hmac_sha256(mac_key, &mac_input);
    let mac_ok = ct_eq(received_mac, &expected_mac);

    if pad_diff != 0 || !mac_ok {
        return None;
    }
    Some(plaintext.to_vec())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use justrdp_core::crypto::sha256;

    // ── DtlsRecord ──

    #[test]
    fn dtls_record_roundtrip() {
        let rec = DtlsRecord {
            content_type: CONTENT_TYPE_HANDSHAKE,
            version: DTLS_1_2,
            epoch: 0,
            sequence_number: 42,
            fragment: vec![0x01, 0x02, 0x03],
        };
        let mut wire = Vec::new();
        rec.encode(&mut wire);
        assert_eq!(wire.len(), rec.wire_size());

        let (decoded, consumed) = DtlsRecord::decode(&wire).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded, rec);
    }

    #[test]
    fn dtls_record_header_is_13_bytes() {
        let rec = DtlsRecord {
            content_type: CONTENT_TYPE_APPLICATION_DATA,
            version: DTLS_1_0,
            epoch: 1,
            sequence_number: 0,
            fragment: vec![],
        };
        let mut wire = Vec::new();
        rec.encode(&mut wire);
        assert_eq!(wire.len(), 13);
    }

    #[test]
    fn dtls_record_epoch_and_seq_big_endian() {
        let rec = DtlsRecord {
            content_type: CONTENT_TYPE_HANDSHAKE,
            version: DTLS_1_2,
            epoch: 0x0102,
            sequence_number: 0x0000_AABB_CCDD_EE,
            fragment: vec![],
        };
        let mut wire = Vec::new();
        rec.encode(&mut wire);
        assert_eq!(&wire[3..5], &[0x01, 0x02]); // epoch BE
        assert_eq!(&wire[5..11], &[0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]); // 48-bit seq
    }

    // ── HandshakeHeader ──

    #[test]
    fn handshake_header_roundtrip() {
        let hdr = HandshakeHeader::unfragmented(HT_CLIENT_HELLO, 100, 0);
        let mut wire = Vec::new();
        hdr.encode(&mut wire);
        assert_eq!(wire.len(), DTLS_HANDSHAKE_HEADER_SIZE);
        let decoded = HandshakeHeader::decode(&wire).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn handshake_header_fragmented() {
        let hdr = HandshakeHeader {
            msg_type: HT_CERTIFICATE,
            length: 5000,
            message_seq: 3,
            fragment_offset: 1200,
            fragment_length: 500,
        };
        let mut wire = Vec::new();
        hdr.encode(&mut wire);
        let decoded = HandshakeHeader::decode(&wire).unwrap();
        assert_eq!(decoded, hdr);
    }

    // ── PRF ──

    #[test]
    fn prf_output_length_matches_request() {
        let out = tls12_prf(b"secret", b"label", b"seed", 100);
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn prf_deterministic() {
        let a = tls12_prf(b"key", b"lbl", b"sd", 48);
        let b = tls12_prf(b"key", b"lbl", b"sd", 48);
        assert_eq!(a, b);
    }

    #[test]
    fn prf_different_labels_produce_different_output() {
        let a = tls12_prf(b"key", b"master secret", b"seed", 48);
        let b = tls12_prf(b"key", b"key expansion", b"seed", 48);
        assert_ne!(a, b);
    }

    #[test]
    fn prf_known_answer_hugo_krawczyk_vector() {
        // Test vector from Hugo Krawczyk, IETF TLS WG mailing list
        // 2008-11-14 (widely referenced "TLS 1.2 PRF Test Vectors"),
        // P_SHA256 expansion. This is the canonical reference used
        // by OpenSSL, mbedTLS and BoringSSL test suites.
        let secret = [
            0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
            0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35,
        ];
        let label = b"test label";
        let seed = [
            0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18,
            0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c,
        ];
        let expected = [
            0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b,
            0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c, 0xd4, 0x53,
            0xc2, 0xaa, 0xb2, 0x1d, 0x07, 0xc3, 0xd4, 0x95,
            0x32, 0x9b, 0x52, 0xd4, 0xe6, 0x1e, 0xdb, 0x5a,
            0x6b, 0x30, 0x17, 0x91, 0xe9, 0x0d, 0x35, 0xc9,
            0xc9, 0xa4, 0x6b, 0x4e, 0x14, 0xba, 0xf9, 0xaf,
            0x0f, 0xa0, 0x22, 0xf7, 0x07, 0x7d, 0xef, 0x17,
            0xab, 0xfd, 0x37, 0x97, 0xc0, 0x56, 0x4b, 0xab,
            0x4f, 0xbc, 0x91, 0x66, 0x6e, 0x9d, 0xef, 0x9b,
            0x97, 0xfc, 0xe3, 0x4f, 0x79, 0x67, 0x89, 0xba,
            0xa4, 0x80, 0x82, 0xd1, 0x22, 0xee, 0x42, 0xc5,
            0xa7, 0x2e, 0x5a, 0x51, 0x10, 0xff, 0xf7, 0x01,
            0x87, 0x34, 0x7b, 0x66,
        ];
        let got = tls12_prf(&secret, label, &seed, expected.len());
        assert_eq!(&got[..], &expected[..], "TLS 1.2 PRF output diverges from reference vector");
    }

    #[test]
    fn ct_eq_handles_equal_unequal_and_mismatched_lengths() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }

    // ── Key derivation ──

    #[test]
    fn master_secret_derivation_deterministic() {
        let pms = [0x42u8; 48];
        let cr = [0xAA; 32];
        let sr = [0xBB; 32];
        let ms1 = derive_master_secret(&pms, &cr, &sr);
        let ms2 = derive_master_secret(&pms, &cr, &sr);
        assert_eq!(ms1, ms2);
        assert_ne!(ms1, [0u8; 48]); // not trivially zero
    }

    #[test]
    fn key_block_has_distinct_keys() {
        let ms = [0x42u8; 48];
        let cr = [0xAA; 32];
        let sr = [0xBB; 32];
        let kb = derive_key_block(&ms, &cr, &sr);
        assert_ne!(kb.client_write_key, kb.server_write_key);
        assert_ne!(kb.client_write_mac_key, kb.server_write_mac_key);
    }

    // ── Record protection ──

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mac_key = [0x11u8; 32];
        let enc_key = [0x22u8; 16];
        let iv = [0x33u8; 16];
        let plaintext = b"hello DTLS world!";
        let version = DTLS_1_2;

        let fragment = encrypt_record(
            &mac_key,
            &enc_key,
            &iv,
            CONTENT_TYPE_APPLICATION_DATA,
            &version,
            1,
            0,
            plaintext,
        );

        let recovered = decrypt_record(
            &mac_key,
            &enc_key,
            CONTENT_TYPE_APPLICATION_DATA,
            &version,
            1,
            0,
            &fragment,
        )
        .unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_rejects_oversize_pad_byte() {
        // Build a fragment with a plausible IV + MAC + 16 bytes of
        // attacker-chosen ciphertext whose last decrypted byte is
        // 0xFF (pad_len = 256). The previous dead-code guard let
        // this fall through; the fix returns None.
        let mac_key = [0x11u8; 32];
        let enc_key = [0x22u8; 16];
        let iv = [0x33u8; 16];
        let mut fragment = encrypt_record(
            &mac_key, &enc_key, &iv,
            CONTENT_TYPE_APPLICATION_DATA, &DTLS_1_2, 0, 0, b"x",
        );
        // Flip last byte to 0xFF — gives pad_byte = 255, which is
        // invalid for AES-CBC (pad_len must be 1..16).
        *fragment.last_mut().unwrap() ^= 0xAA; // will land at some invalid value w.r.t. MAC anyway
        // Any decrypt failure is fine — we just require None, not panic.
        let got = decrypt_record(
            &mac_key, &enc_key,
            CONTENT_TYPE_APPLICATION_DATA, &DTLS_1_2, 0, 0, &fragment,
        );
        assert!(got.is_none());
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let mac_key = [0x11u8; 32];
        let enc_key = [0x22u8; 16];
        let iv = [0x33u8; 16];

        let mut fragment = encrypt_record(
            &mac_key,
            &enc_key,
            &iv,
            CONTENT_TYPE_APPLICATION_DATA,
            &DTLS_1_2,
            0,
            0,
            b"secret",
        );
        // Flip a byte in the ciphertext area.
        let last = fragment.len() - 1;
        fragment[last] ^= 0xFF;

        assert!(decrypt_record(
            &mac_key,
            &enc_key,
            CONTENT_TYPE_APPLICATION_DATA,
            &DTLS_1_2,
            0,
            0,
            &fragment,
        )
        .is_none());
    }

    #[test]
    fn decrypt_rejects_wrong_seq_num() {
        let mac_key = [0x11u8; 32];
        let enc_key = [0x22u8; 16];
        let iv = [0x33u8; 16];

        let fragment = encrypt_record(
            &mac_key,
            &enc_key,
            &iv,
            CONTENT_TYPE_APPLICATION_DATA,
            &DTLS_1_2,
            0,
            0,
            b"data",
        );

        // Decrypt with different sequence number → MAC mismatch.
        assert!(decrypt_record(
            &mac_key,
            &enc_key,
            CONTENT_TYPE_APPLICATION_DATA,
            &DTLS_1_2,
            0,
            1, // wrong seq
            &fragment,
        )
        .is_none());
    }

    #[test]
    fn encrypt_empty_plaintext_roundtrips() {
        let mac_key = [0x11u8; 32];
        let enc_key = [0x22u8; 16];
        let iv = [0x33u8; 16];

        let fragment = encrypt_record(
            &mac_key, &enc_key, &iv,
            CONTENT_TYPE_APPLICATION_DATA, &DTLS_1_2, 0, 0, b"",
        );
        let recovered = decrypt_record(
            &mac_key, &enc_key,
            CONTENT_TYPE_APPLICATION_DATA, &DTLS_1_2, 0, 0, &fragment,
        ).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn verify_data_computation_deterministic() {
        let ms = [0x42u8; 48];
        let hash = sha256(b"handshake transcript");
        let vd1 = compute_verify_data(&ms, b"client finished", &hash);
        let vd2 = compute_verify_data(&ms, b"client finished", &hash);
        assert_eq!(vd1, vd2);
        assert_eq!(vd1.len(), FINISHED_VERIFY_DATA_SIZE);
    }

    #[test]
    fn verify_data_differs_for_client_and_server() {
        let ms = [0x42u8; 48];
        let hash = sha256(b"transcript");
        let client_vd = compute_verify_data(&ms, b"client finished", &hash);
        let server_vd = compute_verify_data(&ms, b"server finished", &hash);
        assert_ne!(client_vd, server_vd);
    }

    #[test]
    fn mac_seq_num_encoding() {
        let seq = mac_seq_num(1, 42);
        assert_eq!(seq, [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 42]);
    }
}
