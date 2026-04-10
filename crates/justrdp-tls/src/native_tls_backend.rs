#![forbid(unsafe_code)]

//! native-tls based TLS backend.
//!
//! Unlike rustls, native-tls (which wraps SChannel on Windows, SecureTransport
//! on macOS, and OpenSSL on Linux) does not expose a per-certificate callback
//! hook during the TLS handshake. The only trust controls it offers are the
//! coarse `danger_accept_invalid_certs` boolean and OS-trust-store delegation.
//!
//! To still honor a user-supplied [`ServerCertVerifier`], this backend uses
//! **post-handshake verification**:
//!
//! 1. The handshake is driven with `danger_accept_invalid_certs(true)` so any
//!    leaf certificate is temporarily accepted.
//! 2. Once the handshake completes, the peer certificate is extracted and
//!    passed to the user's [`ServerCertVerifier::verify`] method.
//! 3. On [`CertDecision::Reject`], the TLS stream is dropped immediately and
//!    a [`TlsError::Handshake`] is returned so no application bytes flow.
//!
//! This produces the same *trust outcome* as the rustls backend but the
//! rejection lands one round-trip later. For RDP that is acceptable: no
//! credentials or session data are transmitted until CredSSP runs *after*
//! TLS, so a rejected native-tls handshake leaks only the TLS handshake
//! itself (which is observable to any on-path adversary anyway).

use std::io::{Read, Write};
use std::sync::Arc;

use crate::verifier::{CertDecision, ServerCertVerifier};
use crate::{AcceptAll, ReadWrite, TlsError, TlsUpgradeResult, TlsUpgrader, ERR_CERT_DER_PARSE, ERR_CERT_REJECTED};

/// Trust mode for [`NativeTlsUpgrader`].
enum TrustMode {
    /// Native-tls drives verification against the OS trust store during
    /// the handshake. The user-supplied verifier is not consulted.
    OsTrustStore,
    /// Native-tls is told to accept any leaf during the handshake, and
    /// verification is performed by calling the user's
    /// [`ServerCertVerifier`] with the extracted certificate afterwards.
    UserVerifier(Arc<dyn ServerCertVerifier>),
}

/// TLS upgrader using the `native-tls` library (platform TLS).
///
/// By default, this accepts self-signed certificates via an [`AcceptAll`]
/// verifier. Use [`with_verifier()`](Self::with_verifier) to inject a custom
/// [`ServerCertVerifier`] (e.g. [`PinnedSpki`](crate::PinnedSpki)), or
/// [`with_verification()`](Self::with_verification) to delegate entirely to
/// the OS trust store.
pub struct NativeTlsUpgrader {
    mode: TrustMode,
}

impl NativeTlsUpgrader {
    /// Create a new upgrader with [`AcceptAll`] (mstsc.exe-like behavior).
    pub fn new() -> Self {
        Self::with_verifier(Arc::new(AcceptAll))
    }

    /// Create an upgrader that delegates certificate validation to a
    /// user-supplied [`ServerCertVerifier`].
    ///
    /// Note that verification runs *after* the TLS handshake completes;
    /// see the module-level docs for the rationale.
    pub fn with_verifier(verifier: Arc<dyn ServerCertVerifier>) -> Self {
        Self {
            mode: TrustMode::UserVerifier(verifier),
        }
    }

    /// Create an upgrader that verifies the certificate chain against the
    /// OS trust store during the handshake. Rejects self-signed certs.
    ///
    /// In this mode the user verifier is not consulted — native-tls (and
    /// the underlying platform TLS library) performs the full verification.
    pub fn with_verification() -> Self {
        Self {
            mode: TrustMode::OsTrustStore,
        }
    }
}

impl Default for NativeTlsUpgrader {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsUpgrader for NativeTlsUpgrader {
    type Stream = native_tls::TlsStream<Box<dyn ReadWrite>>;

    fn upgrade<S: Read + Write + 'static>(
        &self,
        stream: S,
        server_name: &str,
    ) -> Result<TlsUpgradeResult<Self::Stream>, TlsError> {
        let mut builder = native_tls::TlsConnector::builder();
        if matches!(self.mode, TrustMode::UserVerifier(_)) {
            // Accept any leaf during the handshake; the user's verifier
            // runs post-handshake on the extracted certificate.
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }

        let connector = builder
            .build()
            .map_err(|e| TlsError::Handshake(e.to_string()))?;

        let boxed_stream: Box<dyn ReadWrite> = Box::new(stream);
        let tls_stream = connector
            .connect(server_name, boxed_stream)
            .map_err(|e| match e {
                native_tls::HandshakeError::Failure(err) => TlsError::Handshake(err.to_string()),
                // Unreachable for blocking streams. Non-blocking streams are not
                // supported — see TlsUpgrader::upgrade() doc.
                native_tls::HandshakeError::WouldBlock(_) => TlsError::Handshake(
                    "handshake would block (non-blocking stream not supported)".into(),
                ),
            })?;

        let cert_der = extract_peer_cert_der(&tls_stream)?;

        // Post-handshake verification for the UserVerifier mode. In
        // OsTrustStore mode the handshake itself would have failed if the
        // cert were untrusted, so nothing more to check.
        if let TrustMode::UserVerifier(verifier) = &self.mode {
            match verifier.verify(&cert_der, server_name) {
                CertDecision::Accept | CertDecision::AcceptOnce => {}
                CertDecision::Reject => {
                    return Err(TlsError::Handshake(ERR_CERT_REJECTED.into()));
                }
            }
        }

        // Extract SPKI for the CredSSP pubKeyAuth channel binding.
        let server_public_key = crate::extract_spki_from_cert_der(&cert_der)
            .ok_or_else(|| TlsError::PublicKeyExtraction(ERR_CERT_DER_PARSE.into()))?;

        Ok(TlsUpgradeResult {
            stream: tls_stream,
            server_public_key,
        })
    }
}

/// Pull the leaf certificate DER out of a completed native-tls handshake.
fn extract_peer_cert_der(
    tls_stream: &native_tls::TlsStream<Box<dyn ReadWrite>>,
) -> Result<Vec<u8>, TlsError> {
    let cert = tls_stream
        .peer_certificate()
        .map_err(|e| TlsError::PublicKeyExtraction(e.to_string()))?
        .ok_or(TlsError::NoPeerCertificate)?;

    cert.to_der()
        .map_err(|e| TlsError::PublicKeyExtraction(format!("failed to get DER: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_tls_upgrader_default_uses_accept_all() {
        // Just verify construction works — actual verifier behavior is
        // covered by the verifier module tests and the integration tests.
        let _upgrader = NativeTlsUpgrader::new();
        let _default = NativeTlsUpgrader::default();
    }

    #[test]
    fn native_tls_upgrader_accepts_custom_verifier() {
        let _upgrader = NativeTlsUpgrader::with_verifier(Arc::new(AcceptAll));
    }

    #[test]
    fn native_tls_connector_builds_no_verify() {
        let mut builder = native_tls::TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        let connector = builder.build();
        assert!(connector.is_ok(), "connector should build with no-verify settings");
    }

    #[test]
    fn native_tls_connector_builds_with_verify() {
        let builder = native_tls::TlsConnector::builder();
        let connector = builder.build();
        assert!(connector.is_ok(), "connector should build with default verify settings");
    }
}
