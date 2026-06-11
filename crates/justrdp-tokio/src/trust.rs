//! Server-certificate trust policies for the TLS upgrade (issue #36, plan.md §22).
//!
//! slice-2 shipped a deliberately permissive verifier (accept-any) so the connect sequence could
//! be built before validation existed. This module replaces it with a caller-chosen
//! [`TrustPolicy`]: real chain/SAN validation by default, and accept-any only behind an
//! explicitly danger-named opt-in. The policy decides the rustls `ServerCertVerifier`; the
//! handshake itself still runs in the adapter loop.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::BuilderVerifierExt;

/// How the connect decides whether to trust the server's TLS certificate.
///
/// The default is [`TrustPolicy::Chain`] — never accept-any. An untrusted, name-mismatched, or
/// (for TOFU) changed certificate fails the `tls-handshake` stage with
/// [`ConnectFailure::TlsHandshake`](crate::ConnectFailure::TlsHandshake); the connect never
/// reaches NLA, so credentials are never exposed to an unauthenticated peer.
#[derive(Debug, Clone, Default)]
pub enum TrustPolicy {
    /// Chain-of-trust + SAN/hostname validation against the host **as the caller dialed it**,
    /// using the **operating-system trust store** (`rustls-platform-verifier`). Real RDP server
    /// certificates are overwhelmingly issued by enterprise CAs that live in the OS store; a
    /// Mozilla-roots-only verifier would reject most legitimate deployments.
    #[default]
    Chain,
    /// Accept **any** certificate, with no validation of any kind — the connection is open to
    /// man-in-the-middle interception. Lab and test use only; never reachable via `Default`.
    DangerAcceptAny,
}

/// The rustls client config for the connect's TLS upgrade, with the verifier chosen by `trust`.
/// The `ring` crypto provider is selected explicitly so no process-default provider needs
/// installing. Default protocol versions (TLS 1.2 and 1.3) are kept — CredSSP/NLA over TLS 1.3
/// was verified against the real VM (slice-3).
pub(crate) fn client_config(trust: &TrustPolicy) -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default TLS protocol versions");
    let config = match trust {
        TrustPolicy::Chain => builder.with_platform_verifier()?.with_no_client_auth(),
        TrustPolicy::DangerAcceptAny => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { provider }))
            .with_no_client_auth(),
    };
    Ok(config)
}

/// A `ServerCertVerifier` that accepts every certificate and signature — the implementation
/// detail of [`TrustPolicy::DangerAcceptAny`], constructible only through that variant.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
