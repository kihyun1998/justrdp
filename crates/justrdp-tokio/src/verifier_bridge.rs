#![forbid(unsafe_code)]

//! Adapter from [`justrdp_tls::ServerCertVerifier`] to
//! [`rustls::client::danger::ServerCertVerifier`].
//!
//! v1's [`AsyncRdpClient::connect_with_verifier`] takes the
//! high-level `justrdp-tls` trait — a single `verify(cert_der,
//! server_name) -> CertDecision` method, intentionally simpler than
//! rustls's full ceremony. To use that verifier with our
//! `tokio_rustls`-based `NativeTlsUpgrade`, we wrap it as a
//! rustls-shaped verifier here.
//!
//! The pattern mirrors `justrdp_tls::rustls_backend::VerifierBridge`
//! (which is `pub(crate)` in that crate). We re-implement instead
//! of exporting because:
//!
//! * It's ~50 LoC and trivial.
//! * The bridge is specifically for the tokio-rustls path; pulling
//!   it out of justrdp-tls would couple that crate to rustls types
//!   in its public API.
//!
//! [`AsyncRdpClient::connect_with_verifier`]: crate::AsyncRdpClient::connect_with_verifier

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use justrdp_tls::{CertDecision, ServerCertVerifier as UserVerifier};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified,
    ServerCertVerifier as RustlsServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::native_tls::NativeTlsUpgrade;

/// Build a [`NativeTlsUpgrade`] whose certificate validation routes
/// through the user-supplied [`UserVerifier`]. Convenience wrapper
/// — the heavy lifting is in [`VerifierBridge`].
pub(crate) fn build_native_tls_upgrade_with_verifier(
    server_name: &str,
    verifier: Arc<dyn UserVerifier>,
) -> Result<NativeTlsUpgrade, justrdp_async::TransportError> {
    let bridge = Arc::new(VerifierBridge::new(verifier));
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(bridge)
        .with_no_client_auth();
    NativeTlsUpgrade::from_connector(TlsConnector::from(Arc::new(config)), server_name)
}

/// rustls-shaped wrapper around an `Arc<dyn UserVerifier>`. The
/// `verify_server_cert` arm delegates to the user; signature
/// verification is delegated to the same dangerous-no-verify
/// implementation rustls uses internally for its skip-validation
/// example. We do not validate signatures separately — the user's
/// verifier owns the entire trust decision (typical patterns:
/// pinned SPKI, click-through-to-accept).
struct VerifierBridge {
    user: Arc<dyn UserVerifier>,
}

impl core::fmt::Debug for VerifierBridge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Don't try to render the user verifier — it is a `dyn`
        // trait object without `Debug` and the contents (pinned
        // fingerprints, click-through state) are sensitive enough
        // to keep out of formatted output.
        f.debug_struct("VerifierBridge").finish_non_exhaustive()
    }
}

impl VerifierBridge {
    fn new(user: Arc<dyn UserVerifier>) -> Self {
        Self { user }
    }
}

impl RustlsServerCertVerifier for VerifierBridge {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let sn = match server_name {
            ServerName::DnsName(dns) => dns.as_ref().to_string(),
            ServerName::IpAddress(ip) => core::net::IpAddr::from(*ip).to_string(),
            _ => String::new(),
        };
        match self.user.verify(end_entity.as_ref(), &sn) {
            CertDecision::Accept | CertDecision::AcceptOnce => Ok(ServerCertVerified::assertion()),
            CertDecision::Reject => Err(tokio_rustls::rustls::Error::General(format!(
                "rejected by user-supplied verifier"
            ))),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        // Delegated trust: if the user accepted the cert, we accept
        // the signature too. Same model as `justrdp-tls::VerifierBridge`.
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Cover every signature scheme RDP servers actually use
        // (RSA-PKCS1, RSA-PSS, ECDSA-P256/P384, Ed25519). Identical
        // list as `NativeTlsUpgrade::dangerous_no_verify`'s.
        alloc::vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_tls::AcceptAll;

    #[test]
    fn build_native_tls_upgrade_with_accept_all_verifier_succeeds() {
        let upgrader = build_native_tls_upgrade_with_verifier(
            "rdp.example.com",
            Arc::new(AcceptAll),
        );
        assert!(upgrader.is_ok());
    }

    #[test]
    fn build_with_invalid_server_name_returns_protocol_error() {
        // Whitespace-bearing server name is invalid for ServerName.
        let err = build_native_tls_upgrade_with_verifier(
            "not a valid host",
            Arc::new(AcceptAll),
        )
        .unwrap_err();
        assert_eq!(err.kind(), justrdp_async::TransportErrorKind::Protocol);
    }
}
