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
    cert.tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .map(<[u8]>::to_vec)
        // `None` only if the BIT STRING is not byte-aligned, which a valid public key never is.
        .ok_or(TlsCertError::PublicKeyEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// One real certificate, generated once and reused as the mutation base.
    ///
    /// **Why a base at all, rather than only random bytes.** `Certificate::from_der` rejects a
    /// buffer at its outer tag almost immediately, so a generator that only produces random
    /// bytes asserts that the decoder refuses garbage — not that it survives something shaped
    /// like a certificate. #241 measured the difference: 300k small mutations of a real
    /// certificate produced **387 successful extractions**, i.e. they were reaching the decoder,
    /// while undirected buffers reached none. That is the same defect shape this repo already
    /// recorded once, where an `nscodec` property generated `1u8..=7` and ran green over a live
    /// panic; a generator bounded away from the interesting path asserts the generator.
    fn certificate_der() -> &'static [u8] {
        static CERT: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        CERT.get_or_init(|| {
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("rcgen generates a self-signed certificate")
                .cert
                .der()
                .to_vec()
        })
    }

    /// Truncate the base certificate to `keep` of its length, then overwrite `edits` bytes.
    fn mutated(keep: f64, edits: &[(proptest::sample::Index, u8)]) -> Vec<u8> {
        let base = certificate_der();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let len = ((base.len() as f64) * keep) as usize;
        let mut der = base[..len.min(base.len())].to_vec();
        for (index, byte) in edits {
            if !der.is_empty() {
                let at = index.index(der.len());
                der[at] = *byte;
            }
        }
        der
    }

    proptest! {
        /// [untrusted decode never panics](../../../docs/map/invariant/untrusted-decode-never-panics.md)
        /// over the input space that actually reaches `x509_cert`'s decoder.
        #[test]
        fn extract_subject_public_key_never_panics_on_a_mutated_certificate(
            keep in 0.0f64..=1.0,
            edits in proptest::collection::vec((any::<proptest::sample::Index>(), any::<u8>()), 0..4),
        ) {
            let _ = extract_subject_public_key(&mutated(keep, &edits));
        }

        /// And over undirected bytes, which is the shape a hostile server is free to send even
        /// though it exercises the outer tag rather than the structure behind it. Kept as a
        /// *second* property rather than folded in, so neither generator can be mistaken for
        /// covering what the other reaches.
        #[test]
        fn extract_subject_public_key_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..2048),
        ) {
            let _ = extract_subject_public_key(&bytes);
        }
    }

    /// **The generator's reach, asserted rather than assumed.** A no-panic property is only worth
    /// its runtime if its inputs get past the first byte, and nothing about a green property says
    /// they did. This pins that the mutation strategy still lands inside the decoder often enough
    /// to matter; if `rcgen` or `x509-cert` ever changes such that every mutant bounces off the
    /// outer tag, this goes red while the properties above stay green.
    ///
    /// **Measured when written: 355 of 512** single-byte mutants still extract a key, so the
    /// sweep lands well inside the structure rather than scraping its edge.
    #[test]
    fn the_mutation_generator_still_reaches_the_decoder() {
        let base = certificate_der();
        let mut extracted = 0usize;
        // A deterministic sweep rather than a random one: flip one byte at each of 512 evenly
        // spaced offsets over the whole certificate.
        for step in 0..512usize {
            let at = step * base.len() / 512;
            let mut der = base.to_vec();
            der[at] ^= 0xFF;
            if extract_subject_public_key(&der).is_ok() {
                extracted += 1;
            }
        }
        assert!(
            extracted > 0,
            "no single-byte mutant reached a successful extraction — the generator is asserting              the outer tag, not the decoder"
        );
    }

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
            full_spki
                .windows(inner.len())
                .any(|w| w == inner.as_slice()),
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
