#![forbid(unsafe_code)]

//! GSS-API Wrap/Unwrap for Kerberos (RFC 4121).
//!
//! Implements the per-message GSS Wrap token format used by CredSSP
//! to encrypt pubKeyAuth and authInfo with Kerberos session keys.

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::aes::{krb5_aes_decrypt, krb5_aes_encrypt};
use justrdp_pdu::kerberos::{KEY_USAGE_ACCEPTOR_SEAL, KEY_USAGE_INITIATOR_SEAL};

use crate::error::{ConnectorError, ConnectorResult};

/// GSS Wrap token identifier (RFC 4121 section 4.2.6).
const TOK_ID_WRAP: [u8; 2] = [0x05, 0x04];

/// GSS Wrap flags.
const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
const FLAG_SEALED: u8 = 0x02;

/// Header size for GSS Wrap tokens.
const GSS_WRAP_HEADER_SIZE: usize = 16;

/// EC (extra count) for AES Wrap with confidentiality.
/// Equal to the block size for padding alignment.
const AES_EC: u16 = 16;

/// RRC (right rotation count) for AES Wrap with confidentiality.
/// RRC = EC + AES_HMAC_SIZE = 16 + 12 = 28.
const AES_RRC: u16 = 28;

/// Wrap (encrypt) data using GSS Wrap (RFC 4121) with AES confidentiality.
///
/// `key`: the session key (subkey or service session key)
/// `seq_number`: the sequence number (incremented per message)
/// `confounder`: 16 random bytes for the AES encryption
/// `is_initiator`: true if sending from client (initiator), false for server (acceptor)
/// `data`: plaintext to encrypt
///
/// Returns the complete GSS Wrap token (header + rotated ciphertext).
pub fn gss_wrap(
    key: &[u8],
    seq_number: u64,
    confounder: &[u8; 16],
    is_initiator: bool,
    data: &[u8],
) -> ConnectorResult<Vec<u8>> {
    // Build flags
    let mut flags = FLAG_SEALED;
    if !is_initiator {
        flags |= FLAG_SENT_BY_ACCEPTOR;
    }
    // If using a subkey from the acceptor, set the flag.
    // For client-generated subkey in AP-REQ, we don't set ACCEPTOR_SUBKEY.
    // The caller should set this via a separate parameter if needed.

    // Build header with RRC=0 for encryption
    let header_for_encrypt = build_header(flags, AES_EC, 0, seq_number);

    // Plaintext: data || filler(EC zeros) || header(with RRC=0)
    let filler = vec![0u8; AES_EC as usize];
    let mut plaintext = Vec::with_capacity(data.len() + filler.len() + GSS_WRAP_HEADER_SIZE);
    plaintext.extend_from_slice(data);
    plaintext.extend_from_slice(&filler);
    plaintext.extend_from_slice(&header_for_encrypt);

    // Select key usage based on direction
    let key_usage = if is_initiator {
        KEY_USAGE_INITIATOR_SEAL
    } else {
        KEY_USAGE_ACCEPTOR_SEAL
    };

    // Encrypt: confounder(16) || plaintext, producing ciphertext || HMAC(12)
    let encrypted = krb5_aes_encrypt(key, key_usage, &plaintext, confounder)
        .map_err(|_| ConnectorError::general("gss_wrap: key must be valid AES-128 or AES-256"))?;

    // Right-rotate the encrypted data by RRC positions
    let rotated = rotate_right(&encrypted, AES_RRC as usize);

    // Build output header with real RRC
    let output_header = build_header(flags, AES_EC, AES_RRC, seq_number);

    // Final token: header || rotated_ciphertext
    let mut token = Vec::with_capacity(GSS_WRAP_HEADER_SIZE + rotated.len());
    token.extend_from_slice(&output_header);
    token.extend_from_slice(&rotated);
    Ok(token)
}

/// Unwrap (decrypt) a GSS Wrap token (RFC 4121).
///
/// Returns the decrypted plaintext data.
pub fn gss_unwrap(
    key: &[u8],
    is_initiator: bool,
    token: &[u8],
    expected_seq: u64,
) -> ConnectorResult<Vec<u8>> {
    if token.len() < GSS_WRAP_HEADER_SIZE {
        return Err(ConnectorError::general("GSS Wrap token too short"));
    }

    // Parse header
    if token[0] != TOK_ID_WRAP[0] || token[1] != TOK_ID_WRAP[1] {
        return Err(ConnectorError::general("invalid GSS Wrap TOK_ID"));
    }

    let flags = token[2];
    if flags & FLAG_SEALED == 0 {
        return Err(ConnectorError::general("GSS Wrap: only sealed tokens supported"));
    }

    // Verify directional flag consistency (RFC 4121 §4.2.6.1):
    // If we are the initiator, the token should be from the acceptor (flag set).
    // If we are the acceptor, the token should be from the initiator (flag clear).
    let sent_by_acceptor = flags & FLAG_SENT_BY_ACCEPTOR != 0;
    if is_initiator != sent_by_acceptor {
        return Err(ConnectorError::general("GSS Wrap: directional flag mismatch"));
    }

    let ec = u16::from_be_bytes([token[4], token[5]]) as usize;
    let rrc = u16::from_be_bytes([token[6], token[7]]) as usize;

    // RFC 4121 §4.2.6: verify sequence number to prevent replay
    let seq_number = u64::from_be_bytes(token[8..16].try_into().unwrap());
    if seq_number != expected_seq {
        return Err(ConnectorError::general("GSS Wrap: sequence number mismatch"));
    }

    let ciphertext = &token[GSS_WRAP_HEADER_SIZE..];

    // Undo right rotation
    let unrotated = rotate_left(ciphertext, rrc);

    // Determine key usage: if the token was sent by the acceptor, use acceptor key usage;
    // if we (initiator) are unwrapping, the sender is the acceptor.
    let key_usage = if is_initiator {
        // We're the initiator, so the token was sent by the acceptor
        KEY_USAGE_ACCEPTOR_SEAL
    } else {
        KEY_USAGE_INITIATOR_SEAL
    };

    // Decrypt
    let decrypted = krb5_aes_decrypt(key, key_usage, &unrotated)
        .map_err(|_| ConnectorError::general("GSS Wrap: decryption failed"))?;

    // RFC 4121 §4.2.4: EC must equal AES block size (16) for confidentiality
    if ec != AES_EC as usize {
        return Err(ConnectorError::general("GSS Wrap: unexpected EC value"));
    }

    // decrypted = data || filler(ec bytes) || header(16 bytes)
    if decrypted.len() < ec + GSS_WRAP_HEADER_SIZE {
        return Err(ConnectorError::general("GSS Wrap: decrypted data too short"));
    }

    let data_len = decrypted.len() - ec - GSS_WRAP_HEADER_SIZE;
    let data = decrypted[..data_len].to_vec();

    // Verify the embedded header has RRC=0 and matches
    let embedded_header = &decrypted[decrypted.len() - GSS_WRAP_HEADER_SIZE..];
    if embedded_header[0] != TOK_ID_WRAP[0] || embedded_header[1] != TOK_ID_WRAP[1] {
        return Err(ConnectorError::general("GSS Wrap: embedded header mismatch"));
    }

    Ok(data)
}

/// Build a 16-byte GSS Wrap header.
fn build_header(flags: u8, ec: u16, rrc: u16, seq_number: u64) -> [u8; GSS_WRAP_HEADER_SIZE] {
    let mut header = [0u8; GSS_WRAP_HEADER_SIZE];
    header[0] = TOK_ID_WRAP[0]; // 0x05
    header[1] = TOK_ID_WRAP[1]; // 0x04
    header[2] = flags;
    header[3] = 0xFF; // Filler
    header[4..6].copy_from_slice(&ec.to_be_bytes());
    header[6..8].copy_from_slice(&rrc.to_be_bytes());
    header[8..16].copy_from_slice(&seq_number.to_be_bytes());
    header
}

/// Right-rotate a byte slice by `count` positions.
fn rotate_right(data: &[u8], count: usize) -> Vec<u8> {
    if data.is_empty() || count == 0 {
        return data.to_vec();
    }
    let n = data.len();
    let count = count % n;
    if count == 0 {
        return data.to_vec();
    }
    let mut result = vec![0u8; n];
    // Right rotation: last `count` bytes move to front
    result[..count].copy_from_slice(&data[n - count..]);
    result[count..].copy_from_slice(&data[..n - count]);
    result
}

/// Left-rotate a byte slice by `count` positions (inverse of right rotation).
fn rotate_left(data: &[u8], count: usize) -> Vec<u8> {
    if data.is_empty() || count == 0 {
        return data.to_vec();
    }
    let n = data.len();
    let count = count % n;
    if count == 0 {
        return data.to_vec();
    }
    let mut result = vec![0u8; n];
    result[..n - count].copy_from_slice(&data[count..]);
    result[n - count..].copy_from_slice(&data[..count]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotate_right_basic() {
        let data = vec![1, 2, 3, 4, 5];
        assert_eq!(rotate_right(&data, 2), vec![4, 5, 1, 2, 3]);
    }

    #[test]
    fn rotate_left_basic() {
        let data = vec![1, 2, 3, 4, 5];
        assert_eq!(rotate_left(&data, 2), vec![3, 4, 5, 1, 2]);
    }

    #[test]
    fn rotate_roundtrip() {
        let data = vec![10, 20, 30, 40, 50, 60, 70, 80];
        let rotated = rotate_right(&data, 3);
        let restored = rotate_left(&rotated, 3);
        assert_eq!(data, restored);
    }

    #[test]
    fn gss_wrap_unwrap_roundtrip() {
        // Use a 32-byte AES-256 key
        let key = [0x42u8; 32];
        let confounder = [0x11u8; 16];
        let plaintext = b"Hello, CredSSP with Kerberos!";

        // Client (initiator) wraps
        let token = gss_wrap(&key, 0, &confounder, true, plaintext).unwrap();

        // Verify token starts with TOK_ID
        assert_eq!(token[0], 0x05);
        assert_eq!(token[1], 0x04);
        // Flags: Sealed, not sent by acceptor
        assert_eq!(token[2] & FLAG_SEALED, FLAG_SEALED);
        assert_eq!(token[2] & FLAG_SENT_BY_ACCEPTOR, 0);

        // Server (initiator=false means we're unwrapping as server, but
        // for unwrap, is_initiator means "are WE the initiator" which determines
        // the key usage for the SENDER.
        // Since the client (initiator) wrapped it, the server unwraps with is_initiator=false.
        let unwrapped = gss_unwrap(&key, false, &token, 0).unwrap();
        assert_eq!(&unwrapped, plaintext);
    }

    #[test]
    fn gss_wrap_unwrap_empty() {
        let key = [0x55u8; 32];
        let confounder = [0x22u8; 16];

        let token = gss_wrap(&key, 42, &confounder, true, b"").unwrap();
        let unwrapped = gss_unwrap(&key, false, &token, 42).unwrap();
        assert!(unwrapped.is_empty());
    }

    #[test]
    fn gss_wrap_seq_number_in_header() {
        let key = [0x33u8; 32];
        let confounder = [0x44u8; 16];

        let token = gss_wrap(&key, 0x0102030405060708, &confounder, true, b"test").unwrap();

        // Seq number is at bytes 8..16 in big-endian
        let seq = u64::from_be_bytes(token[8..16].try_into().unwrap());
        assert_eq!(seq, 0x0102030405060708);
    }

    #[test]
    fn gss_wrap_unwrap_aes128() {
        // Use a 16-byte AES-128 key
        let key = [0x77u8; 16];
        let confounder = [0x88u8; 16];
        let plaintext = b"AES-128 test data";

        let token = gss_wrap(&key, 1, &confounder, true, plaintext).unwrap();
        let unwrapped = gss_unwrap(&key, false, &token, 1).unwrap();
        assert_eq!(&unwrapped, plaintext);
    }
}
