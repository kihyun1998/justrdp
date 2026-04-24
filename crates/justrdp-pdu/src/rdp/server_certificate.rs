#![forbid(unsafe_code)]

//! Server Certificate parsing for Standard RDP Security -- MS-RDPBCGR 2.2.1.4.3.1
//!
//! Supports both:
//! - Proprietary certificates (dwVersion & 0x7FFFFFFF == 1)
//! - X.509 certificate chains (dwVersion & 0x7FFFFFFF == 2)
//!
//! The proprietary format contains:
//! - `PROPRIETARYSERVERCERTIFICATE`: signature algorithm, key algorithm,
//!   RSA public key blob, and signature blob
//! - The signature is verified against the Terminal Services public key

use alloc::vec::Vec;

use justrdp_core::bignum::BigUint;
use justrdp_core::crypto;
use justrdp_core::{ReadCursor, DecodeResult, DecodeError};

// ── Constants ──

/// Signature algorithm: RSA with MD5.
const SIGNATURE_ALG_RSA: u32 = 0x00000001;
/// Key algorithm: RSA.
const KEY_EXCHANGE_ALG_RSA: u32 = 0x00000001;

/// Magic value in RSA_PUBLIC_KEY blob: "RSA1" (little-endian).
const RSA1_MAGIC: u32 = 0x31415352;

/// Blob type: BB_RSA_KEY_BLOB.
const BB_RSA_KEY_BLOB: u16 = 0x0006;
/// Blob type: BB_RSA_SIGNATURE_BLOB.
const BB_RSA_SIGNATURE_BLOB: u16 = 0x0008;

/// Terminal Services signing key (MS-RDPBCGR 5.3.3.1.1).
/// This is the well-known public key used to verify proprietary certificate signatures.
/// Terminal Services signing key modulus (little-endian).
const TERMINAL_SERVICES_MODULUS: [u8; 64] = [
    0x3d, 0x3a, 0x5e, 0xbd, 0x72, 0x43, 0x3e, 0xc9,
    0x4d, 0xbb, 0xc1, 0x1e, 0x4a, 0xba, 0x5f, 0xcb,
    0x3e, 0x88, 0x20, 0x87, 0xef, 0xf5, 0xc1, 0xe2,
    0xd7, 0xb7, 0x6b, 0x9a, 0xf2, 0x52, 0x45, 0x95,
    0xce, 0x63, 0x65, 0x6b, 0x58, 0x3a, 0xfe, 0xef,
    0x7c, 0xe7, 0xbf, 0xfe, 0x3d, 0xf6, 0x5c, 0x7d,
    0x6c, 0x5e, 0x06, 0x09, 0x1a, 0xf5, 0x61, 0xbb,
    0x20, 0x93, 0x09, 0x5f, 0x05, 0x6d, 0xea, 0x87,
];

/// Terminal Services signing key public exponent.
///
/// **Not 65537.** The TSSK predates modern RSA conventions: its public
/// exponent is `0xC088_7B5B`, declared in FreeRDP's source as the
/// little-endian byte sequence `[0x5b, 0x7b, 0x88, 0xc0]` (see
/// `libfreerdp/crypto/certificate.c::tssk_exponent`). Verified here
/// via a `(m^d)^e mod n == m` roundtrip test -- the RSA-standard
/// 0x00010001 value does NOT form a valid keypair with the TSSK
/// modulus / private exponent.
const TERMINAL_SERVICES_EXPONENT: u32 = 0xC088_7B5B;

/// Terminal Services signing key private exponent (MS-RDPBCGR §5.3.3.1.2).
///
/// This is a **publicly-known test key**: the same value ships in FreeRDP
/// (`libfreerdp/crypto/privatekey.c::tssk_privateExponent`), IronRDP,
/// NeutrinoRDP, and xrdp because every proprietary-certificate-issuing
/// server needs to sign the cert blob with it, and every client verifies
/// against the matching public key in `TERMINAL_SERVICES_MODULUS`.
///
/// The key is deliberately weak (512-bit RSA) and was never intended for
/// actual security -- it gates the proprietary-certificate "test" path
/// that `PROTOCOL_RDP` loopback uses. Real deployments use TLS with X.509
/// certificates instead (Enhanced RDP Security).
const TERMINAL_SERVICES_PRIVATE_EXPONENT: [u8; 64] = [
    0x87, 0xa7, 0x19, 0x32, 0xda, 0x11, 0x87, 0x55,
    0x58, 0x00, 0x16, 0x16, 0x25, 0x65, 0x68, 0xf8,
    0x24, 0x3e, 0xe6, 0xfa, 0xe9, 0x67, 0x49, 0x94,
    0xcf, 0x92, 0xcc, 0x33, 0x99, 0xe8, 0x08, 0x60,
    0x17, 0x9a, 0x12, 0x9f, 0x24, 0xdd, 0xb1, 0x24,
    0x99, 0xc7, 0x3a, 0xb8, 0x0a, 0x7b, 0x0d, 0xdd,
    0x35, 0x07, 0x79, 0x17, 0x0b, 0x51, 0x9b, 0xb3,
    0xc7, 0x10, 0x01, 0x13, 0xe7, 0x3f, 0xf3, 0x5f,
];

/// Length of the Terminal Services 512-bit RSA signature (and modulus).
const TSSK_SIGNATURE_SIZE: usize = 64;

/// Wire length of the proprietary certificate signature blob: the
/// 64-byte RSA signature plus 8 bytes of `0x00` padding that
/// MS-RDPBCGR §2.2.1.4.3.1.1 requires after the signature.
const PROPRIETARY_SIGNATURE_BLOB_LEN: usize = TSSK_SIGNATURE_SIZE + 8;

// ── Public types ──

/// Parsed RSA public key from a server certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerRsaPublicKey {
    /// Public exponent (usually 65537).
    pub exponent: u32,
    /// Modulus in little-endian byte order.
    pub modulus: Vec<u8>,
    /// Key length in bits.
    pub bit_len: u32,
}

impl ServerRsaPublicKey {
    /// Modulus length in bytes (= `bit_len / 8`, rounded up).
    pub fn modulus_len_bytes(&self) -> usize {
        ((self.bit_len as usize) + 7) / 8
    }
}

/// Certificate type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateType {
    Proprietary,
    X509,
}

/// Parsed server certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCertificate {
    pub cert_type: CertificateType,
    pub public_key: ServerRsaPublicKey,
}

// ── Parsing ──

/// Parse a server certificate from raw bytes (from `ServerSecurityData.server_certificate`).
///
/// MS-RDPBCGR 2.2.1.4.3.1 SERVER_CERTIFICATE
pub fn parse_server_certificate(data: &[u8]) -> DecodeResult<ServerCertificate> {
    let mut cursor = ReadCursor::new(data);

    let dw_version = cursor.read_u32_le("ServerCert::dwVersion")?;
    let cert_version = dw_version & 0x7FFF_FFFF;

    match cert_version {
        1 => parse_proprietary_certificate(&mut cursor),
        2 => parse_x509_certificate_chain(&mut cursor),
        _ => Err(DecodeError::unexpected_value(
            "ServerCertificate",
            "dwVersion",
            "expected 1 (proprietary) or 2 (X.509)",
        )),
    }
}

/// Parse a proprietary server certificate.
///
/// MS-RDPBCGR 2.2.1.4.3.1.1 PROPRIETARYSERVERCERTIFICATE
fn parse_proprietary_certificate(src: &mut ReadCursor<'_>) -> DecodeResult<ServerCertificate> {
    // Capture the start of the signed region (MS-RDPBCGR §5.3.3.1.1):
    // the signature covers `dwSigAlgId` through end of the public-key
    // blob (= wPublicKeyBlobLen bytes after the blob header fields).
    // `peek_remaining()` here is the complete byte window from
    // `dwSigAlgId` onwards; we slice out the signed region after we
    // learn `pk_blob_len`.
    let signed_region_window: &[u8] = src.peek_remaining();

    let sig_alg = src.read_u32_le("PropCert::dwSigAlgId")?;
    let key_alg = src.read_u32_le("PropCert::dwKeyAlgId")?;

    if sig_alg != SIGNATURE_ALG_RSA {
        return Err(DecodeError::unexpected_value(
            "ProprietaryCert", "dwSigAlgId", "expected SIGNATURE_ALG_RSA (1)",
        ));
    }
    if key_alg != KEY_EXCHANGE_ALG_RSA {
        return Err(DecodeError::unexpected_value(
            "ProprietaryCert", "dwKeyAlgId", "expected KEY_EXCHANGE_ALG_RSA (1)",
        ));
    }

    // Public key blob
    let pk_blob_type = src.read_u16_le("PropCert::wPublicKeyBlobType")?;
    if pk_blob_type != BB_RSA_KEY_BLOB {
        return Err(DecodeError::unexpected_value(
            "ProprietaryCert", "wPublicKeyBlobType", "expected BB_RSA_KEY_BLOB (6)",
        ));
    }
    let pk_blob_len = src.read_u16_le("PropCert::wPublicKeyBlobLen")? as usize;
    let pk_blob_start = src.pos();
    if src.remaining() < pk_blob_len {
        return Err(DecodeError::not_enough_bytes("PropCert::pkBlob", pk_blob_len, src.remaining()));
    }
    let public_key = parse_rsa_public_key(src)?;
    // Skip any remaining bytes in the blob
    let consumed = src.pos() - pk_blob_start;
    if pk_blob_len > consumed {
        src.skip(pk_blob_len - consumed, "PropCert::pkBlobPad")?;
    }

    // Signed region = dwSigAlgId(4) + dwKeyAlgId(4) + wPublicKeyBlobType(2)
    // + wPublicKeyBlobLen(2) + pk_blob(pk_blob_len) = 12 + pk_blob_len bytes.
    let signed_region_len = 12 + pk_blob_len;
    if signed_region_window.len() < signed_region_len {
        return Err(DecodeError::not_enough_bytes(
            "PropCert::signedRegion",
            signed_region_len,
            signed_region_window.len(),
        ));
    }
    let signed_region = signed_region_window[..signed_region_len].to_vec();

    // Signature blob
    let sig_blob_type = src.read_u16_le("PropCert::wSignatureBlobType")?;
    if sig_blob_type != BB_RSA_SIGNATURE_BLOB {
        return Err(DecodeError::unexpected_value(
            "ProprietaryCert", "wSignatureBlobType", "expected BB_RSA_SIGNATURE_BLOB (8)",
        ));
    }
    let sig_blob_len = src.read_u16_le("PropCert::wSignatureBlobLen")? as usize;
    let signature = src.read_slice(sig_blob_len, "PropCert::signatureBlob")?;

    // Verify signature using Terminal Services signing key (MS-RDPBCGR 5.3.3.1.1).
    // The signature is RSA(MD5(signed_region)) with the well-known TS key.
    verify_proprietary_signature(&signed_region, &signature[..TSSK_SIGNATURE_SIZE.min(signature.len())])?;

    Ok(ServerCertificate {
        cert_type: CertificateType::Proprietary,
        public_key,
    })
}

/// Parse RSA_PUBLIC_KEY structure.
///
/// ```text
/// magic    (4 bytes LE) = "RSA1" (0x31415352)
/// keylen   (4 bytes LE) = modulus length in bytes
/// bitlen   (4 bytes LE) = modulus length in bits
/// datalen  (4 bytes LE) = max plaintext bytes (bitlen/8 - 1)
/// exponent (4 bytes LE)
/// modulus  (keylen bytes, LE) -- includes 1 byte of zero padding
/// ```
fn parse_rsa_public_key(src: &mut ReadCursor<'_>) -> DecodeResult<ServerRsaPublicKey> {
    let magic = src.read_u32_le("RsaPubKey::magic")?;
    if magic != RSA1_MAGIC {
        return Err(DecodeError::unexpected_value(
            "RsaPublicKey", "magic", "expected RSA1 (0x31415352)",
        ));
    }

    let key_len = src.read_u32_le("RsaPubKey::keylen")? as usize;
    // MS-RDPBCGR: RSA key modulus is at most 4096 bits (512 bytes + 1 padding)
    if key_len > 513 {
        return Err(DecodeError::unexpected_value("RsaPublicKey", "keylen", "exceeds maximum 513"));
    }
    let bit_len = src.read_u32_le("RsaPubKey::bitlen")?;
    let _data_len = src.read_u32_le("RsaPubKey::datalen")?;
    let exponent = src.read_u32_le("RsaPubKey::pubExp")?;

    // Modulus: keylen bytes (last byte is zero padding per MS-RDPBCGR)
    let modulus_raw = src.read_slice(key_len, "RsaPubKey::modulus")?;

    // Strip exactly 1 trailing zero-padding byte (keylen = actual_modulus + 1)
    let modulus_len = key_len.saturating_sub(1);
    let modulus = modulus_raw[..modulus_len].to_vec();

    Ok(ServerRsaPublicKey {
        exponent,
        modulus,
        bit_len,
    })
}

/// Parse X.509 certificate chain.
///
/// MS-RDPBCGR 2.2.1.4.3.1.2 X509_CERTIFICATE_CHAIN
fn parse_x509_certificate_chain(src: &mut ReadCursor<'_>) -> DecodeResult<ServerCertificate> {
    let num_certs = src.read_u32_le("X509Chain::NumCertBlobs")? as usize;

    if num_certs == 0 {
        return Err(DecodeError::unexpected_value(
            "X509CertChain", "NumCertBlobs", "expected at least 1 certificate",
        ));
    }
    // Cap at a reasonable limit to prevent excessive iteration from malicious input
    if num_certs > 16 {
        return Err(DecodeError::unexpected_value(
            "X509CertChain", "NumCertBlobs", "too many certificates (max 16)",
        ));
    }

    // Read all certificate blobs; the last one is the server's leaf cert.
    let mut last_cert_data = &[][..];
    for i in 0..num_certs {
        let cert_len = src.read_u32_le("X509Chain::cbCertSize")? as usize;
        // Individual cert blob should not exceed the outer certificate limit
        if cert_len > 16384 {
            return Err(DecodeError::unexpected_value("X509CertChain", "cbCertSize", "exceeds maximum 16384"));
        }
        let cert_data = src.read_slice(cert_len, "X509Chain::abCert")?;
        if i == num_certs - 1 {
            last_cert_data = cert_data;
        }
    }

    // Skip padding (8 + 4 bytes) after the cert chain
    // MS-RDPBCGR: 8 bytes padding + 4 bytes padding
    let remaining = src.len() - src.pos();
    if remaining > 0 {
        let skip = remaining.min(12);
        src.skip(skip, "X509Chain::padding")?;
    }

    // Extract RSA public key from the X.509 DER certificate
    let public_key = extract_rsa_key_from_x509_der(last_cert_data)?;

    Ok(ServerCertificate {
        cert_type: CertificateType::X509,
        public_key,
    })
}

/// Extract RSA public key from an X.509 DER certificate.
///
/// Minimal DER parsing to extract the SubjectPublicKeyInfo → RSA modulus + exponent.
fn extract_rsa_key_from_x509_der(cert: &[u8]) -> DecodeResult<ServerRsaPublicKey> {
    let mut pos = 0;

    // Certificate SEQUENCE
    let (_, cert_end) = der_read_sequence(cert, &mut pos)?;
    let _ = cert_end; // entire cert

    // TBSCertificate SEQUENCE
    let (_, tbs_end) = der_read_sequence(cert, &mut pos)?;

    // Skip: version [0] EXPLICIT (optional), serialNumber, signature algorithm
    // version: context-tagged [0]
    if pos < tbs_end && cert[pos] == 0xA0 {
        der_skip_tlv(cert, &mut pos)?;
    }
    // serialNumber INTEGER
    der_skip_tlv(cert, &mut pos)?;
    // signature AlgorithmIdentifier SEQUENCE
    der_skip_tlv(cert, &mut pos)?;
    // issuer Name SEQUENCE
    der_skip_tlv(cert, &mut pos)?;
    // validity SEQUENCE
    der_skip_tlv(cert, &mut pos)?;
    // subject Name SEQUENCE
    der_skip_tlv(cert, &mut pos)?;

    // subjectPublicKeyInfo SEQUENCE
    let (_, spki_end) = der_read_sequence(cert, &mut pos)?;

    // algorithm AlgorithmIdentifier SEQUENCE (skip)
    der_skip_tlv(cert, &mut pos)?;

    // subjectPublicKey BIT STRING
    if pos >= spki_end || cert[pos] != 0x03 {
        return Err(DecodeError::unexpected_value(
            "X509", "subjectPublicKey", "expected BIT STRING",
        ));
    }
    pos += 1;
    let _bs_len = der_read_length(cert, &mut pos)?;
    if pos >= cert.len() {
        return Err(DecodeError::not_enough_bytes("X509::bitstring", 1, 0));
    }
    let _unused_bits = cert[pos];
    pos += 1;

    // The BIT STRING content is a DER-encoded RSAPublicKey SEQUENCE
    let (_, rsa_end) = der_read_sequence(cert, &mut pos)?;

    // modulus INTEGER
    if pos >= rsa_end || cert[pos] != 0x02 {
        return Err(DecodeError::unexpected_value("X509", "modulus", "expected INTEGER"));
    }
    pos += 1;
    let mod_len = der_read_length(cert, &mut pos)?;
    let mod_start = pos;
    pos += mod_len;

    // exponent INTEGER
    if pos >= rsa_end || cert[pos] != 0x02 {
        return Err(DecodeError::unexpected_value("X509", "exponent", "expected INTEGER"));
    }
    pos += 1;
    let exp_len = der_read_length(cert, &mut pos)?;

    // Parse exponent (big-endian → u32)
    if exp_len == 0 || exp_len > 4 {
        return Err(DecodeError::unexpected_value(
            "X509", "exponent length", "expected 1-4 bytes",
        ));
    }
    let mut exponent: u32 = 0;
    for i in 0..exp_len {
        exponent = (exponent << 8) | cert[pos + i] as u32;
    }

    // Parse modulus (big-endian, may have leading zero for sign)
    let mut mod_bytes = &cert[mod_start..mod_start + mod_len];
    if !mod_bytes.is_empty() && mod_bytes[0] == 0 {
        mod_bytes = &mod_bytes[1..]; // skip leading zero
    }

    // Convert modulus to little-endian for consistency with proprietary format
    let mut modulus_le: Vec<u8> = mod_bytes.to_vec();
    modulus_le.reverse();

    let bit_len = (mod_bytes.len() * 8) as u32;

    Ok(ServerRsaPublicKey {
        exponent,
        modulus: modulus_le,
        bit_len,
    })
}

// ── Proprietary certificate signature verification ──

/// Verify the proprietary certificate signature using the Terminal Services signing key.
///
/// MS-RDPBCGR 5.3.3.1.1: The signature is an RSA operation on MD5(public_key_blob)
/// using the well-known Terminal Services private key. We verify by:
/// 1. Compute MD5 of the public key blob
/// 2. RSA decrypt the signature with the TS public key (m^e mod n)
/// 3. Compare the decrypted value with the MD5 hash
fn verify_proprietary_signature(pk_blob: &[u8], signature: &[u8]) -> DecodeResult<()> {
    let md5_hash = crypto::md5(pk_blob);

    // RSA verify: decrypt signature with TS public key
    // Signature is in little-endian byte order
    let sig_int = BigUint::from_le_bytes(signature);
    let n = BigUint::from_le_bytes(&TERMINAL_SERVICES_MODULUS);
    let e = BigUint::from_u32(TERMINAL_SERVICES_EXPONENT);

    let decrypted = sig_int.mod_exp(&e, &n);
    let decrypted_bytes = decrypted.to_le_bytes_padded(64);

    // The decrypted value should start with the MD5 hash (16 bytes)
    // followed by zero padding per PKCS#1.
    // Use constant-time comparison to prevent timing oracle attacks.
    if decrypted_bytes.len() < 16 {
        return Err(DecodeError::unexpected_value(
            "ProprietaryCert", "signature", "signature verification failed",
        ));
    }
    let mut diff = 0u8;
    for (a, b) in decrypted_bytes[..16].iter().zip(md5_hash.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(DecodeError::unexpected_value(
            "ProprietaryCert", "signature", "signature verification failed",
        ));
    }

    Ok(())
}

// ── DER parsing helpers ──

fn der_read_sequence(data: &[u8], pos: &mut usize) -> DecodeResult<(usize, usize)> {
    if *pos >= data.len() || data[*pos] != 0x30 {
        return Err(DecodeError::unexpected_value("DER", "tag", "expected SEQUENCE (0x30)"));
    }
    *pos += 1;
    let len = der_read_length(data, pos)?;
    let start = *pos;
    Ok((start, start + len))
}

fn der_read_length(data: &[u8], pos: &mut usize) -> DecodeResult<usize> {
    if *pos >= data.len() {
        return Err(DecodeError::not_enough_bytes("DER::length", 1, 0));
    }
    let first = data[*pos];
    *pos += 1;

    if first < 0x80 {
        Ok(first as usize)
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || *pos + num_bytes > data.len() {
            return Err(DecodeError::not_enough_bytes("DER::longLength", 1, 0));
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | data[*pos + i] as usize;
        }
        *pos += num_bytes;
        // Cap at TPKT maximum to prevent oversized allocations
        if len > 65535 {
            return Err(DecodeError::unexpected_value("DER", "length", "exceeds maximum 65535"));
        }
        Ok(len)
    }
}

fn der_skip_tlv(data: &[u8], pos: &mut usize) -> DecodeResult<()> {
    if *pos >= data.len() {
        return Err(DecodeError::not_enough_bytes("DER::skipTlv", 1, 0));
    }
    *pos += 1; // tag
    let len = der_read_length(data, pos)?;
    if *pos + len > data.len() {
        return Err(DecodeError::not_enough_bytes("DER::skipTlvData", 1, 0));
    }
    *pos += len;
    Ok(())
}

// ── Proprietary certificate emit (server side) ──

/// Sign a proprietary-certificate public-key blob with the Terminal
/// Services 512-bit test private key (MS-RDPBCGR §5.3.3.1.1).
///
/// The signed message is the PKCS-like padded MD5 digest:
///
/// ```text
///     MD5(pk_blob) (16 bytes)
///     || 0x00         (1 byte)
///     || 0xFF repeated (modulus_size - 16 - 2) bytes
///     || 0x01         (1 byte)
/// ```
///
/// The LE-interpreted padded value is raised to the power
/// `TERMINAL_SERVICES_PRIVATE_EXPONENT` modulo
/// `TERMINAL_SERVICES_MODULUS`. The result is returned as 64 LE bytes
/// -- exactly the form the client-side [`verify_proprietary_signature`]
/// expects to recover via `sig^e mod n`.
fn sign_proprietary_pk_blob(pk_blob: &[u8]) -> [u8; TSSK_SIGNATURE_SIZE] {
    let md5_hash = crypto::md5(pk_blob);

    // MS-RDPBCGR §5.3.3.1.1 padding: hash || 0x00 || 0xFF * N || 0x01.
    let mut padded = [0u8; TSSK_SIGNATURE_SIZE];
    padded[..16].copy_from_slice(&md5_hash);
    padded[16] = 0x00;
    padded[17..TSSK_SIGNATURE_SIZE - 1].fill(0xFF);
    padded[TSSK_SIGNATURE_SIZE - 1] = 0x01;

    // s = padded^d mod n (raw RSA -- the spec uses the LE byte order for
    // both the encoded integer and the signature blob).
    let m = BigUint::from_le_bytes(&padded);
    let d = BigUint::from_le_bytes(&TERMINAL_SERVICES_PRIVATE_EXPONENT);
    let n = BigUint::from_le_bytes(&TERMINAL_SERVICES_MODULUS);
    let s = m.mod_exp(&d, &n);

    let bytes = s.to_le_bytes_padded(TSSK_SIGNATURE_SIZE);
    let mut out = [0u8; TSSK_SIGNATURE_SIZE];
    out.copy_from_slice(&bytes);
    out
}

/// Build the `RSA_PUBLIC_KEY` wire blob for `key`, matching the layout
/// that [`parse_rsa_public_key`] reads (MS-RDPBCGR §2.2.1.4.3.1.1.1).
///
/// Wire shape: `magic(4) || keylen(4) || bitlen(4) || datalen(4)
/// || pubExp(4) || modulus(keylen)` -- where `keylen =
/// modulus_size_bytes + 1` and the trailing byte is zero padding that
/// the decoder strips.
fn encode_rsa_public_key_blob(key: &ServerRsaPublicKey) -> Vec<u8> {
    let modulus_size = key.modulus_len_bytes();
    // `keylen` on the wire is `modulus_size + 1` because the wire form
    // keeps one byte of zero-pad after the modulus (MS-RDPBCGR 2.2.1.4.3.1.1.1).
    let key_len_on_wire = (modulus_size + 1) as u32;
    let bit_len = key.bit_len;
    // `datalen` per spec = bitlen/8 - 1 = max plaintext bytes encryptable.
    let data_len = bit_len.saturating_sub(8) / 8;

    let mut blob = Vec::with_capacity(5 * 4 + modulus_size + 1);
    blob.extend_from_slice(&RSA1_MAGIC.to_le_bytes());
    blob.extend_from_slice(&key_len_on_wire.to_le_bytes());
    blob.extend_from_slice(&bit_len.to_le_bytes());
    blob.extend_from_slice(&data_len.to_le_bytes());
    blob.extend_from_slice(&key.exponent.to_le_bytes());
    blob.extend_from_slice(&key.modulus);
    // Pad modulus up to exactly `modulus_size` bytes (callers sometimes
    // drop trailing zero bytes) and then append the spec-mandated zero pad.
    if key.modulus.len() < modulus_size {
        blob.resize(blob.len() + (modulus_size - key.modulus.len()), 0x00);
    }
    blob.push(0x00);
    blob
}

/// Encode a proprietary server certificate blob for inclusion in the
/// `SERVER_CERTIFICATE` field of a `ServerSecurityData` GCC block
/// (MS-RDPBCGR §2.2.1.4.3.1.1).
///
/// Returns the full wire form starting with `dwVersion = 0x00000001`
/// (Proprietary) through the end of the signature blob.
///
/// The signature is computed with the Terminal Services 512-bit test
/// key described in MS-RDPBCGR §5.3.3.1.2 -- the same key every other
/// RDP server implementation (FreeRDP / IronRDP / xrdp) uses. Callers
/// wishing to ship an X.509 chain instead should construct the
/// `dwVersion = 2` form directly (not covered by this helper).
///
/// # Constraints
///
/// * `key.modulus` MUST be `key.modulus_len_bytes()` bytes long (leading
///   zeros are permitted; trailing zeros are disallowed by most clients
///   because the modulus byte position carries meaning).
/// * `key.bit_len` MUST be a positive multiple of 8 and MUST be at most
///   `4096` -- any larger is rejected by typical client parsers
///   (including this crate's own parser at a cap of 513 bytes for
///   `keylen`).
pub fn encode_proprietary_certificate(key: &ServerRsaPublicKey) -> Vec<u8> {
    let pk_blob = encode_rsa_public_key_blob(key);
    let pk_blob_len = pk_blob.len() as u16;

    // PROPRIETARYSERVERCERTIFICATE header up to the public-key blob
    // (§2.2.1.4.3.1.1). The signature covers the cert bytes from
    // `dwSigAlgId` through the end of the public-key blob, inclusive.
    let mut signed_region = Vec::with_capacity(4 + 4 + 2 + 2 + pk_blob.len());
    signed_region.extend_from_slice(&SIGNATURE_ALG_RSA.to_le_bytes());
    signed_region.extend_from_slice(&KEY_EXCHANGE_ALG_RSA.to_le_bytes());
    signed_region.extend_from_slice(&BB_RSA_KEY_BLOB.to_le_bytes());
    signed_region.extend_from_slice(&pk_blob_len.to_le_bytes());
    signed_region.extend_from_slice(&pk_blob);

    let signature = sign_proprietary_pk_blob(&signed_region);

    // dwVersion = 0x00000001 (Proprietary) + signed_region + signature
    // blob (BB_RSA_SIGNATURE_BLOB + length + signature + 8-byte zero pad).
    let mut out = Vec::with_capacity(4 + signed_region.len() + 4 + PROPRIETARY_SIGNATURE_BLOB_LEN);
    out.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // dwVersion
    out.extend_from_slice(&signed_region);
    out.extend_from_slice(&BB_RSA_SIGNATURE_BLOB.to_le_bytes());
    out.extend_from_slice(&(PROPRIETARY_SIGNATURE_BLOB_LEN as u16).to_le_bytes());
    out.extend_from_slice(&signature);
    out.extend_from_slice(&[0u8; 8]); // spec-mandated 8-byte zero pad after signature
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn parse_proprietary_certificate_basic() {
        // Construct a minimal proprietary certificate
        let mut data = Vec::new();

        // dwVersion: proprietary (1) with temporary flag bit 31
        data.extend_from_slice(&0x0000_0001u32.to_le_bytes());
        // dwSigAlgId: SIGNATURE_ALG_RSA
        data.extend_from_slice(&SIGNATURE_ALG_RSA.to_le_bytes());
        // dwKeyAlgId: KEY_EXCHANGE_ALG_RSA
        data.extend_from_slice(&KEY_EXCHANGE_ALG_RSA.to_le_bytes());

        // Public key blob
        data.extend_from_slice(&BB_RSA_KEY_BLOB.to_le_bytes());       // wPublicKeyBlobType
        let pk_blob_len = 4 + 4 + 4 + 4 + 4 + 65; // RSA_PUBLIC_KEY struct: magic(4)+keylen(4)+bitlen(4)+datalen(4)+exp(4)+modulus(65)
        data.extend_from_slice(&(pk_blob_len as u16).to_le_bytes());  // wPublicKeyBlobLen

        // RSA_PUBLIC_KEY
        data.extend_from_slice(&RSA1_MAGIC.to_le_bytes());   // magic
        data.extend_from_slice(&65u32.to_le_bytes());         // keylen (64 + 1 padding)
        data.extend_from_slice(&512u32.to_le_bytes());        // bitlen
        data.extend_from_slice(&63u32.to_le_bytes());         // datalen (bitlen/8 - 1)
        data.extend_from_slice(&65537u32.to_le_bytes());      // exponent

        // Modulus: 64 bytes of 0xFF + 1 byte padding (0x00)
        let mut modulus = vec![0xFFu8; 64];
        modulus.push(0x00); // padding byte
        data.extend_from_slice(&modulus);

        // Signature blob
        data.extend_from_slice(&BB_RSA_SIGNATURE_BLOB.to_le_bytes()); // wSignatureBlobType
        let sig_len = 64u16;
        data.extend_from_slice(&sig_len.to_le_bytes());               // wSignatureBlobLen
        data.extend_from_slice(&vec![0xAA; 64]);                      // signature data

        // Fake signature (0xAA) will fail verification
        let result = parse_server_certificate(&data);
        assert!(result.is_err(), "should fail with invalid signature");
    }

    #[test]
    fn rsa_public_key_magic_check() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // version
        data.extend_from_slice(&SIGNATURE_ALG_RSA.to_le_bytes());
        data.extend_from_slice(&KEY_EXCHANGE_ALG_RSA.to_le_bytes());
        data.extend_from_slice(&BB_RSA_KEY_BLOB.to_le_bytes());
        data.extend_from_slice(&20u16.to_le_bytes());   // blob len
        data.extend_from_slice(&0xDEADBEEFu32.to_le_bytes()); // wrong magic

        assert!(parse_server_certificate(&data).is_err());
    }

    #[test]
    fn invalid_version() {
        let data = 99u32.to_le_bytes();
        assert!(parse_server_certificate(&data).is_err());
    }

    // ──────────────────────────────────────────────────────────────
    // Proprietary certificate emit roundtrip (§11.2a-stdsec S1)
    // ──────────────────────────────────────────────────────────────

    fn fake_server_public_key() -> ServerRsaPublicKey {
        // 512-bit test key material: any 64 bytes work because the
        // client does not verify the modulus semantically; it only
        // uses it for RSA-encrypting the client random.
        let mut modulus = vec![0u8; 64];
        for (i, b) in modulus.iter_mut().enumerate() {
            *b = (i * 7 + 0x11) as u8;
        }
        ServerRsaPublicKey {
            exponent: 0x0001_0001,
            modulus,
            bit_len: 512,
        }
    }

    #[test]
    fn tssk_sign_verify_roundtrip_512bit() {
        // Sanity-check the Terminal Services 512-bit private exponent
        // bytes: sign an arbitrary message with d, then reverse via
        // `m' = sig^e mod n`. If the private exponent bytes are wrong
        // (or in the wrong byte order), the recovered message will
        // differ from the input.
        let msg_bytes = [0x42u8; 64];
        // Clamp to < n so mod_exp composes uniquely.
        let mut msg_small = msg_bytes;
        msg_small[63] &= 0x3F; // ensure m < 2^510 < n
        let m = BigUint::from_le_bytes(&msg_small);
        let d = BigUint::from_le_bytes(&TERMINAL_SERVICES_PRIVATE_EXPONENT);
        let n = BigUint::from_le_bytes(&TERMINAL_SERVICES_MODULUS);
        let e = BigUint::from_u32(TERMINAL_SERVICES_EXPONENT);

        let s = m.mod_exp(&d, &n);
        let m_prime = s.mod_exp(&e, &n);
        assert_eq!(
            m_prime.to_le_bytes_padded(64),
            msg_small.to_vec(),
            "TSSK private exponent must round-trip: (m^d)^e mod n = m"
        );
    }

    #[test]
    fn encode_proprietary_certificate_passes_verify() {
        // The real end-to-end test: emit a cert with our server-side
        // encoder and confirm the existing client-side parser+verifier
        // accepts it. Failure here would mean either the wire layout
        // is off or the signature bytes are wrong.
        let pk = fake_server_public_key();
        let cert = encode_proprietary_certificate(&pk);
        let parsed = parse_server_certificate(&cert)
            .expect("emitted proprietary cert MUST pass client-side signature verify");
        assert_eq!(parsed.cert_type, CertificateType::Proprietary);
        assert_eq!(parsed.public_key.exponent, pk.exponent);
        assert_eq!(parsed.public_key.bit_len, pk.bit_len);
        assert_eq!(parsed.public_key.modulus, pk.modulus);
    }

    #[test]
    fn encode_proprietary_certificate_tampered_bytes_fail_verify() {
        // Flip a bit inside the signed region after signing: the MD5
        // over the signed region changes, so verify_proprietary_signature
        // MUST reject. Confirms signing actually binds the wire bytes,
        // not some constant.
        let pk = fake_server_public_key();
        let mut cert = encode_proprietary_certificate(&pk);
        // Layout: cert[0..4]=dwVersion, cert[4..8]=dwSigAlgId,
        // cert[8..12]=dwKeyAlgId, cert[12..16]=blob type+len,
        // cert[16..36]=RSA1/keylen/bitlen/datalen/pubExp,
        // cert[36..]=modulus. Byte 28 lands inside the bitlen field of
        // the RSA_PUBLIC_KEY blob — still within the signed region, so
        // flipping it invalidates the MD5 and hence the signature.
        cert[28] ^= 0x01;
        assert!(
            parse_server_certificate(&cert).is_err(),
            "tampered public-key blob MUST fail signature verification"
        );
    }

    #[test]
    fn encode_proprietary_certificate_wire_fields_match_spec() {
        // Spot-check the fixed-position fields so a future refactor
        // does not quietly slip an offset (§2.2.1.4.3.1.1).
        let pk = fake_server_public_key();
        let cert = encode_proprietary_certificate(&pk);
        assert_eq!(&cert[0..4], &1u32.to_le_bytes(), "dwVersion = 1");
        assert_eq!(&cert[4..8], &SIGNATURE_ALG_RSA.to_le_bytes());
        assert_eq!(&cert[8..12], &KEY_EXCHANGE_ALG_RSA.to_le_bytes());
        assert_eq!(&cert[12..14], &BB_RSA_KEY_BLOB.to_le_bytes());
        // Signature blob must appear at the end; last 8 bytes are zeros.
        assert_eq!(&cert[cert.len() - 8..], &[0u8; 8]);
    }
}
