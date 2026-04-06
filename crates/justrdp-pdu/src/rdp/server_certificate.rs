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

const TERMINAL_SERVICES_EXPONENT: u32 = 0x00010001; // 65537

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
    // Save the raw public key blob bytes for signature verification
    if src.remaining() < pk_blob_len {
        return Err(DecodeError::not_enough_bytes("PropCert::pkBlob", pk_blob_len, src.remaining()));
    }
    let pk_blob_bytes = src.peek_remaining()[..pk_blob_len].to_vec();
    let public_key = parse_rsa_public_key(src)?;
    // Skip any remaining bytes in the blob
    let consumed = src.pos() - pk_blob_start;
    if pk_blob_len > consumed {
        src.skip(pk_blob_len - consumed, "PropCert::pkBlobPad")?;
    }

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
    // The signature is RSA(MD5(pk_blob)) with the well-known TS key.
    verify_proprietary_signature(&pk_blob_bytes, signature)?;

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
    // followed by zero padding per PKCS#1
    if decrypted_bytes.len() < 16 || decrypted_bytes[..16] != md5_hash {
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
}
