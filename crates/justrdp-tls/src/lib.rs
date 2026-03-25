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
    /// RDP servers commonly use self-signed certificates, so implementations
    /// should provide an option to skip certificate verification.
    fn upgrade<S: Read + Write + 'static>(
        &self,
        stream: S,
        server_name: &str,
    ) -> Result<TlsUpgradeResult<Self::Stream>, TlsError>;
}

// Re-export backend types
#[cfg(feature = "rustls-backend")]
pub use rustls_backend::RustlsUpgrader;

#[cfg(feature = "native-tls-backend")]
pub use native_tls_backend::NativeTlsUpgrader;

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

    Some(spki[pos..end].to_vec())
}

fn der_read_tag_length(data: &[u8], pos: &mut usize) -> Option<(u8, usize)> {
    if *pos >= data.len() {
        return None;
    }
    let tag = data[*pos];
    *pos += 1;

    let length = der_read_length(data, pos)?;
    let end = *pos + length;
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
        if num_bytes == 0 || num_bytes > 4 || *pos + num_bytes > data.len() {
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
