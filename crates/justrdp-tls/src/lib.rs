#![forbid(unsafe_code)]
#![doc = "TLS transport abstraction and backends for JustRDP."]
#![doc = ""]
#![doc = "Provides the [`TlsUpgrader`] trait for upgrading raw TCP streams to TLS,"]
#![doc = "with optional backends for `rustls` and `native-tls`."]

mod danger;

#[cfg(feature = "rustls-backend")]
mod rustls_backend;

#[cfg(feature = "native-tls-backend")]
mod native_tls_backend;

use std::fmt;
use std::io::{Read, Write};

/// Error type for TLS operations.
#[derive(Debug)]
pub enum TlsError {
    /// TLS handshake failed.
    Handshake(String),
    /// Failed to extract server public key.
    PublicKeyExtraction(String),
    /// I/O error during TLS operation.
    Io(std::io::Error),
    /// No peer certificate available.
    NoPeerCertificate,
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handshake(msg) => write!(f, "TLS handshake failed: {msg}"),
            Self::PublicKeyExtraction(msg) => write!(f, "public key extraction failed: {msg}"),
            Self::Io(err) => write!(f, "TLS I/O error: {err}"),
            Self::NoPeerCertificate => write!(f, "no peer certificate available"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for TlsError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Result of a successful TLS upgrade.
pub struct TlsUpgradeResult<S> {
    /// The TLS-wrapped stream.
    pub stream: S,
    /// DER-encoded server public key (SubjectPublicKeyInfo).
    /// Used for CredSSP `pubKeyAuth` channel binding.
    pub server_public_key: Vec<u8>,
}

/// Trait for upgrading a raw TCP stream to a TLS stream.
///
/// Implementations handle the TLS handshake and extract the server's
/// public key for use in CredSSP authentication.
pub trait TlsUpgrader {
    /// The type of the TLS-wrapped stream.
    type Stream: Read + Write;

    /// Perform TLS handshake and upgrade the given stream.
    ///
    /// `server_name` is used for SNI (Server Name Indication).
    /// The provided stream **must be in blocking mode**. Non-blocking streams
    /// are not supported and will result in an error.
    ///
    /// RDP servers commonly use self-signed certificates, so implementations
    /// may provide an option to skip certificate verification.
    fn upgrade<S: Read + Write + 'static>(
        &self,
        stream: S,
        server_name: &str,
    ) -> Result<TlsUpgradeResult<Self::Stream>, TlsError>;
}

/// Trait alias combining [`Read`] and [`Write`], used to box transport streams.
pub trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

// Re-export backend types
#[cfg(feature = "rustls-backend")]
pub use rustls_backend::RustlsUpgrader;

#[cfg(feature = "native-tls-backend")]
pub use native_tls_backend::NativeTlsUpgrader;

// ── Shared constants ──

pub(crate) const ERR_CERT_DER_PARSE: &str = "failed to parse certificate DER";

// ── Shared X.509 DER parsing ──

/// Extract DER-encoded SubjectPublicKeyInfo from an X.509 certificate DER blob.
///
/// X.509 structure:
/// ```text
/// Certificate ::= SEQUENCE {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
/// TBSCertificate ::= SEQUENCE {
///     version         [0] EXPLICIT INTEGER DEFAULT v1,
///     serialNumber         INTEGER,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,  ← extracted
///     ...
/// }
/// ```
pub fn extract_spki_from_cert_der(cert: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;

    // Outer SEQUENCE (Certificate)
    let (_, _cert_end) = der_read_tag_length(cert, &mut pos)?;

    // TBSCertificate SEQUENCE
    let (_, _tbs_end) = der_read_tag_length(cert, &mut pos)?;

    // version [0] EXPLICIT (optional, skip if present)
    if pos < cert.len() && cert[pos] == 0xA0 {
        let (_, _) = der_read_tag_length(cert, &mut pos)?;
        der_skip_tlv(cert, &mut pos)?;
    }

    // serialNumber - skip
    der_skip_tlv(cert, &mut pos)?;
    // signature AlgorithmIdentifier - skip
    der_skip_tlv(cert, &mut pos)?;
    // issuer Name - skip
    der_skip_tlv(cert, &mut pos)?;
    // validity Validity - skip
    der_skip_tlv(cert, &mut pos)?;
    // subject Name - skip
    der_skip_tlv(cert, &mut pos)?;

    // subjectPublicKeyInfo - extract complete TLV
    let spki_start = pos;
    der_skip_tlv(cert, &mut pos)?;

    Some(cert[spki_start..pos].to_vec())
}

/// Extract the SubjectPublicKey BIT STRING value from a DER-encoded SubjectPublicKeyInfo.
///
/// ```text
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm            AlgorithmIdentifier,
///     subjectPublicKey     BIT STRING
/// }
/// ```
///
/// Returns the BIT STRING contents (including the leading unused-bits byte).
/// This is the value MS-CSSP refers to as "SubjectPublicKey sub-field".
pub fn extract_subject_public_key_from_spki(spki: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;

    // Outer SEQUENCE (SubjectPublicKeyInfo)
    let (tag, _seq_end) = der_read_tag_length(spki, &mut pos)?;
    if tag != 0x30 {
        return None; // not a SEQUENCE
    }

    // AlgorithmIdentifier - skip
    der_skip_tlv(spki, &mut pos)?;

    // subjectPublicKey BIT STRING - extract value
    let (tag, end) = der_read_tag_length(spki, &mut pos)?;
    if tag != 0x03 {
        return None; // not a BIT STRING
    }
    if end > spki.len() {
        return None;
    }

    Some(spki[pos..end].to_vec())
}

fn der_read_tag_length(data: &[u8], pos: &mut usize) -> Option<(u8, usize)> {
    if *pos >= data.len() {
        return None;
    }
    let tag = data[*pos];
    *pos += 1;

    let length = der_read_length(data, pos)?;
    let end = (*pos).checked_add(length)?;
    Some((tag, end))
}

fn der_read_length(data: &[u8], pos: &mut usize) -> Option<usize> {
    if *pos >= data.len() {
        return None;
    }

    let first = data[*pos];
    *pos += 1;

    if first < 0x80 {
        Some(first as usize)
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || (*pos).checked_add(num_bytes).map_or(true, |end| end > data.len()) {
            return None;
        }
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | data[*pos + i] as usize;
        }
        *pos += num_bytes;
        Some(length)
    }
}

fn der_skip_tlv(data: &[u8], pos: &mut usize) -> Option<()> {
    let (_, end) = der_read_tag_length(data, pos)?;
    if end > data.len() {
        return None;
    }
    *pos = end;
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DER length encoding helper shared across test builders.
    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len < 0x100 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, len as u8]
        }
    }

    /// Build a minimal self-signed X.509 certificate DER with a known SPKI.
    /// Structure: Certificate SEQUENCE { TBSCertificate, sigAlgo, sigValue }
    /// TBSCertificate: [0] version, serialNumber, sigAlgo, issuer, validity, subject, SPKI
    fn build_test_cert(spki: &[u8]) -> Vec<u8> {
        // Helper: wrap in SEQUENCE tag
        fn seq(content: &[u8]) -> Vec<u8> {
            let mut r = vec![0x30];
            r.extend(der_len(content.len()));
            r.extend_from_slice(content);
            r
        }
        // Helper: encode INTEGER
        fn int(val: u8) -> Vec<u8> {
            vec![0x02, 0x01, val]
        }
        // Helper: encode BIT STRING (unused bits = 0)
        fn bitstr(content: &[u8]) -> Vec<u8> {
            let mut r = vec![0x03];
            r.extend(der_len(content.len() + 1));
            r.push(0x00); // unused bits
            r.extend_from_slice(content);
            r
        }
        // Helper: context tag [0] EXPLICIT
        fn ctx0(content: &[u8]) -> Vec<u8> {
            let mut r = vec![0xA0];
            r.extend(der_len(content.len()));
            r.extend_from_slice(content);
            r
        }

        let version = ctx0(&int(2)); // v3
        let serial = int(1);
        let sig_algo = seq(&[0x06, 0x03, 0x55, 0x04, 0x03]); // dummy OID
        let issuer = seq(&[]); // empty
        let validity = seq(&[]); // empty
        let subject = seq(&[]); // empty

        let mut tbs_body = Vec::new();
        tbs_body.extend_from_slice(&version);
        tbs_body.extend_from_slice(&serial);
        tbs_body.extend_from_slice(&sig_algo);
        tbs_body.extend_from_slice(&issuer);
        tbs_body.extend_from_slice(&validity);
        tbs_body.extend_from_slice(&subject);
        tbs_body.extend_from_slice(spki);

        let tbs = seq(&tbs_body);
        let outer_sig_algo = seq(&[0x06, 0x03, 0x55, 0x04, 0x03]);
        let sig_value = bitstr(&[0xAA, 0xBB]);

        let mut cert_body = Vec::new();
        cert_body.extend_from_slice(&tbs);
        cert_body.extend_from_slice(&outer_sig_algo);
        cert_body.extend_from_slice(&sig_value);

        seq(&cert_body)
    }

    /// Build a minimal SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING }
    fn build_test_spki(pub_key_bytes: &[u8]) -> Vec<u8> {
        let algo = vec![
            0x30, 0x0D, // AlgorithmIdentifier SEQUENCE
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // RSA OID
            0x05, 0x00, // NULL
        ];
        let mut bitstr = vec![0x03];
        let bs_len = pub_key_bytes.len() + 1;
        if bs_len < 0x80 {
            bitstr.push(bs_len as u8);
        } else {
            bitstr.push(0x81);
            bitstr.push(bs_len as u8);
        }
        bitstr.push(0x00); // unused bits
        bitstr.extend_from_slice(pub_key_bytes);

        let total_len = algo.len() + bitstr.len();
        let mut spki = vec![0x30];
        if total_len < 0x80 {
            spki.push(total_len as u8);
        } else {
            spki.push(0x81);
            spki.push(total_len as u8);
        }
        spki.extend_from_slice(&algo);
        spki.extend_from_slice(&bitstr);
        spki
    }

    #[test]
    fn extract_spki_from_cert_roundtrip() {
        let pub_key = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let spki = build_test_spki(&pub_key);
        let cert = build_test_cert(&spki);

        let extracted = extract_spki_from_cert_der(&cert).unwrap();
        assert_eq!(extracted, spki, "extracted SPKI should match original");
    }

    #[test]
    fn extract_spki_without_version_tag() {
        // Build a cert WITHOUT the [0] version tag (v1 implicit default)
        let pub_key = vec![0xAA; 8];
        let spki = build_test_spki(&pub_key);

        // Manually build a TBSCertificate without version [0]
        let serial = vec![0x02, 0x01, 0x01]; // INTEGER 1
        let sig_algo = vec![0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03];
        let issuer = vec![0x30, 0x00];
        let validity = vec![0x30, 0x00];
        let subject = vec![0x30, 0x00];

        let mut tbs_body = Vec::new();
        // No version tag — starts directly with serialNumber
        tbs_body.extend_from_slice(&serial);
        tbs_body.extend_from_slice(&sig_algo);
        tbs_body.extend_from_slice(&issuer);
        tbs_body.extend_from_slice(&validity);
        tbs_body.extend_from_slice(&subject);
        tbs_body.extend_from_slice(&spki);

        let mut tbs = vec![0x30];
        tbs.extend(der_len(tbs_body.len()));
        tbs.extend_from_slice(&tbs_body);

        let outer_sig = vec![0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03];
        let sig_val = vec![0x03, 0x03, 0x00, 0xAA, 0xBB];

        let mut cert_body = Vec::new();
        cert_body.extend_from_slice(&tbs);
        cert_body.extend_from_slice(&outer_sig);
        cert_body.extend_from_slice(&sig_val);

        let mut cert = vec![0x30];
        if cert_body.len() < 0x80 {
            cert.push(cert_body.len() as u8);
        } else {
            cert.push(0x81);
            cert.push(cert_body.len() as u8);
        }
        cert.extend_from_slice(&cert_body);

        let extracted = extract_spki_from_cert_der(&cert).unwrap();
        assert_eq!(extracted, spki, "should extract SPKI from cert without [0] version");
    }

    #[test]
    fn extract_spki_truncated_input() {
        assert!(extract_spki_from_cert_der(&[]).is_none());
        assert!(extract_spki_from_cert_der(&[0x30]).is_none());
        assert!(extract_spki_from_cert_der(&[0x30, 0x03, 0x30, 0x01, 0x00]).is_none());
    }

    #[test]
    fn extract_subject_public_key_roundtrip() {
        let pub_key = vec![0x30, 0x0B, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00];
        let spki = build_test_spki(&pub_key);

        let extracted = extract_subject_public_key_from_spki(&spki).unwrap();
        // Should get BIT STRING contents: unused-bits byte + pub_key
        assert_eq!(extracted[0], 0x00, "first byte should be unused-bits = 0");
        assert_eq!(&extracted[1..], &pub_key[..]);
    }

    #[test]
    fn extract_subject_public_key_non_sequence_returns_none() {
        // Not a SEQUENCE — should return None
        let data = vec![0x04, 0x03, 0x01, 0x02, 0x03]; // OCTET STRING
        assert!(extract_subject_public_key_from_spki(&data).is_none());
    }

    #[test]
    fn extract_subject_public_key_empty_returns_none() {
        assert!(extract_subject_public_key_from_spki(&[]).is_none());
    }

    #[test]
    fn extract_subject_public_key_truncated_returns_none() {
        // SEQUENCE with declared length 0x20 but only 2 bytes of content
        assert!(extract_subject_public_key_from_spki(&[0x30, 0x20, 0x30, 0x00]).is_none());
        // SEQUENCE header only, no content at all
        assert!(extract_subject_public_key_from_spki(&[0x30, 0x05]).is_none());
    }

    #[test]
    fn der_skip_tlv_rejects_oversized_length() {
        // SEQUENCE with declared 4-byte length 0xFFFFFFFF but only 6 bytes total
        let data = [0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut pos = 0;
        assert!(der_skip_tlv(&data, &mut pos).is_none());
    }

    #[test]
    fn der_read_length_rejects_5_byte_length() {
        // 5-byte length encoding (num_bytes=5, exceeds the 4-byte cap)
        let data = [0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00];
        let mut pos = 0;
        assert!(der_read_tag_length(&data, &mut pos).is_none());
    }
}
