//! TLS certificate handling for the connect sequence (sans-IO). The TLS *handshake* itself runs in
//! the I/O adapter (rustls is its own sans-IO state machine — shuttling its records through our
//! connect machine would add nothing; see plan.md §3 and ADR-0002). What the core owns is the pure,
//! RDP-relevant step: given the server's leaf certificate, extract the `subjectPublicKey` that
//! CredSSP later binds to (`pubKeyAuth`, plan.md §0 — FreeRDP/IronRDP convention binds to the
//! certificate's `subjectPublicKey`, the inner BIT STRING of the `SubjectPublicKeyInfo`, **not** the
//! whole `SubjectPublicKeyInfo` and not the whole certificate). Binding to the full SPKI makes a
//! Windows server reject the channel binding and abort the TLS session (proven on the real VM,
//! slice-3): the server hashes only the inner key, so we must too.

use x509_cert::Certificate;
use x509_cert::der::Decode;

/// Why extracting the server public key failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsCertError {
    /// The certificate DER could not be parsed as an X.509 certificate.
    MalformedCertificate,
    /// The parsed certificate's `SubjectPublicKeyInfo` could not be re-encoded to DER.
    PublicKeyEncoding,
}

/// Extract the server's `subjectPublicKey` from its leaf TLS certificate (`cert_der`), returning the
/// inner public-key bytes — the contents of the `SubjectPublicKeyInfo`'s `subjectPublicKey` BIT
/// STRING (for RSA, the DER `RSAPublicKey { modulus, exponent }`), **not** the enclosing
/// `SubjectPublicKeyInfo` and **not** the certificate. This is the exact value CredSSP's `pubKeyAuth`
/// binding hashes (FreeRDP / ironrdp `extract_tls_server_public_key` convention); a Windows server
/// hashes the same inner key and aborts the TLS session if our binding disagrees.
pub fn extract_subject_public_key(cert_der: &[u8]) -> Result<Vec<u8>, TlsCertError> {
    let cert = Certificate::from_der(cert_der).map_err(|_| TlsCertError::MalformedCertificate)?;
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .map(<[u8]>::to_vec)
        // `None` only if the BIT STRING is not byte-aligned, which a valid public key never is.
        .ok_or(TlsCertError::PublicKeyEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_inner_subject_public_key_not_the_whole_spki() {
        // CredSSP's pubKeyAuth binds to the certificate's `subjectPublicKey` — the *inner* BIT STRING
        // contents of the SubjectPublicKeyInfo, NOT the whole SPKI structure (FreeRDP / ironrdp
        // convention). Binding to the full SPKI makes a Windows server reject the channel binding and
        // abort the TLS session — proven on the real VM in slice-3.
        use rcgen::PublicKeyData as _;
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = key.cert.der();
        // `subject_public_key_info()` is the *full* SPKI; the inner key is a proper subset.
        let full_spki = key.signing_key.subject_public_key_info();

        let inner = extract_subject_public_key(cert_der.as_ref()).unwrap();

        assert!(
            inner.len() < full_spki.len(),
            "extracted the whole SPKI ({} bytes) instead of the inner subjectPublicKey",
            inner.len()
        );
        assert!(
            full_spki.windows(inner.len()).any(|w| w == inner.as_slice()),
            "the inner subjectPublicKey must be contained verbatim within the full SPKI"
        );
    }

    #[test]
    fn rejects_a_non_certificate_blob() {
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            extract_subject_public_key(&garbage),
            Err(TlsCertError::MalformedCertificate)
        );
    }
}
