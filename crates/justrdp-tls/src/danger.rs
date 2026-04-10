#![forbid(unsafe_code)]

//! Custom certificate verifier for self-signed RDP server certificates.
//!
//! RDP servers commonly use self-signed certificates that would fail
//! standard TLS verification. This module provides a permissive verifier
//! that accepts any certificate (similar to mstsc.exe default behavior).

#[cfg(feature = "rustls-backend")]
pub(crate) mod rustls_verifier {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    /// Signature-verification pass-through for rustls.
    ///
    /// `verify_server_cert` is intentionally **not** used — [`VerifierBridge`]
    /// owns the certificate trust decision and delegates only TLS signature
    /// verification here. If `verify_server_cert` is called, it returns an
    /// error to surface the unexpected code path immediately.
    #[derive(Debug)]
    pub struct DangerousNoVerify;

    impl ServerCertVerifier for DangerousNoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            // This should never be called; VerifierBridge dispatches
            // trust decisions through the user's ServerCertVerifier.
            Err(Error::General(
                "DangerousNoVerify::verify_server_cert called unexpectedly".into(),
            ))
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use rustls::pki_types::CertificateDer;

        #[test]
        fn verify_server_cert_returns_error() {
            let v = DangerousNoVerify;
            let cert = CertificateDer::from(vec![0u8; 10]);
            let name = ServerName::try_from("example.com").unwrap();
            let result = v.verify_server_cert(&cert, &[], &name, &[], UnixTime::now());
            assert!(result.is_err(), "verify_server_cert must return error — VerifierBridge owns trust decisions");
        }

        // Note: verify_tls12_signature and verify_tls13_signature cannot be
        // unit-tested in isolation because DigitallySignedStruct::new is private.
        // They are exercised indirectly through VerifierBridge in rustls_backend tests.

        #[test]
        fn supported_verify_schemes_is_non_empty() {
            let v = DangerousNoVerify;
            let schemes = v.supported_verify_schemes();
            assert!(!schemes.is_empty(), "must advertise at least one scheme");
            assert!(schemes.contains(&SignatureScheme::RSA_PKCS1_SHA256));
        }
    }
}
