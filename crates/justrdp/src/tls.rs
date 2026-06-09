//! TLS certificate handling for the connect sequence (sans-IO). The TLS *handshake* itself runs in
//! the I/O adapter (rustls is its own sans-IO state machine — shuttling its records through our
//! connect machine would add nothing; see plan.md §3 and ADR-0002). What the core owns is the pure,
//! RDP-relevant step: given the server's leaf certificate, extract the `subjectPublicKey` that
//! CredSSP later binds to (`pubKeyAuth`, plan.md §0 — FreeRDP/IronRDP convention binds to the
//! certificate's `SubjectPublicKeyInfo`, not the whole certificate).

use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

/// Why extracting the server public key failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsCertError {
    /// The certificate DER could not be parsed as an X.509 certificate.
    MalformedCertificate,
    /// The parsed certificate's `SubjectPublicKeyInfo` could not be re-encoded to DER.
    PublicKeyEncoding,
}

/// Extract the server's `subjectPublicKey` from its leaf TLS certificate (`cert_der`), returning the
/// DER-encoded `SubjectPublicKeyInfo` (algorithm identifier + the public key BIT STRING) — the exact
/// bytes `openssl … | openssl rsa -pubin -outform DER` / OpenSSL's `i2d_PUBKEY` produce, and the
/// value CredSSP's public-key binding consumes.
pub fn extract_subject_public_key(cert_der: &[u8]) -> Result<Vec<u8>, TlsCertError> {
    let cert = Certificate::from_der(cert_der).map_err(|_| TlsCertError::MalformedCertificate)?;
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| TlsCertError::PublicKeyEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_subject_public_key_info_from_a_certificate() {
        // A throwaway self-signed cert. The extracted SubjectPublicKeyInfo must be byte-identical to
        // the key pair's own DER — that is what `i2d_PUBKEY` / `openssl rsa -pubin -outform DER`
        // emit, and what CredSSP binds to.
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = key.cert.der();
        let expected_spki = key.key_pair.public_key_der();

        let spki = extract_subject_public_key(cert_der.as_ref()).unwrap();
        assert_eq!(spki, expected_spki);
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
