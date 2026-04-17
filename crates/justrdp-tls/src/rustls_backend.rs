#![forbid(unsafe_code)]

//! rustls-based TLS backend.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier as RustlsServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

use crate::danger::rustls_verifier::DangerousNoVerify;
use crate::verifier::{CertDecision, ServerCertVerifier};
use crate::{AcceptAll, ReadWrite, TlsError, TlsUpgradeResult, TlsUpgrader, ERR_CERT_DER_PARSE, ERR_CERT_REJECTED};

/// TLS upgrader using the `rustls` library.
///
/// By default, this accepts self-signed certificates (common for RDP servers).
/// Use [`with_verification()`](Self::with_verification) for strict certificate validation
/// against the system root store, or [`with_verifier()`](Self::with_verifier) to inject
/// a custom [`ServerCertVerifier`] (e.g. [`PinnedSpki`](crate::PinnedSpki)).
pub struct RustlsUpgrader {
    config: Arc<ClientConfig>,
}

impl RustlsUpgrader {
    /// Create a new upgrader with default settings (no certificate verification).
    ///
    /// RDP servers commonly use self-signed certificates, so this is the
    /// appropriate default for most RDP connections (similar to mstsc.exe).
    pub fn new() -> Self {
        Self::with_verifier(Arc::new(AcceptAll))
    }

    /// Create an upgrader that verifies server certificates against
    /// the system root certificate store.
    pub fn with_verification() -> Self {
        Self {
            config: Arc::new(build_system_roots_config()),
        }
    }

    /// Create an upgrader that delegates certificate validation to a
    /// user-supplied [`ServerCertVerifier`].
    ///
    /// This is the preferred constructor: pass [`AcceptAll`](crate::AcceptAll)
    /// for permissive behavior, [`PinnedSpki`](crate::PinnedSpki) for fingerprint
    /// pinning, or a custom implementation for GUI trust prompts.
    pub fn with_verifier(verifier: Arc<dyn ServerCertVerifier>) -> Self {
        let bridge = Arc::new(VerifierBridge::new(verifier));
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(bridge)
            .with_no_client_auth();
        Self {
            config: Arc::new(config),
        }
    }
}

fn build_system_roots_config() -> ClientConfig {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

impl Default for RustlsUpgrader {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsUpgrader for RustlsUpgrader {
    type Stream = StreamOwned<ClientConnection, Box<dyn ReadWrite>>;

    fn upgrade<S: Read + Write + Send + 'static>(
        &self,
        stream: S,
        server_name: &str,
    ) -> Result<TlsUpgradeResult<Self::Stream>, TlsError> {
        let config = Arc::clone(&self.config);

        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|e| TlsError::Handshake(format!("invalid server name: {e}")))?;

        let conn = ClientConnection::new(config, server_name)
            .map_err(|e| TlsError::Handshake(e.to_string()))?;

        // Box the stream so we have a single concrete type
        let boxed_stream: Box<dyn ReadWrite> = Box::new(stream);
        let mut tls_stream = StreamOwned::new(conn, boxed_stream);

        // Drive the TLS handshake to completion by pumping both read and write
        // directions until the handshake finishes. Requires a blocking stream;
        // non-blocking streams will propagate WouldBlock as TlsError::Io.
        while tls_stream.conn.is_handshaking() {
            tls_stream.conn.complete_io(&mut tls_stream.sock)?;
        }

        // Extract server public key from peer certificate
        let server_public_key = extract_server_public_key(&tls_stream)?;

        Ok(TlsUpgradeResult {
            stream: tls_stream,
            server_public_key,
        })
    }
}

/// Extract DER-encoded SubjectPublicKeyInfo from the server's certificate.
fn extract_server_public_key(
    tls_stream: &StreamOwned<ClientConnection, Box<dyn ReadWrite>>,
) -> Result<Vec<u8>, TlsError> {
    let certs = tls_stream
        .conn
        .peer_certificates()
        .ok_or(TlsError::NoPeerCertificate)?;

    let cert_der = certs
        .first()
        .ok_or(TlsError::NoPeerCertificate)?;

    crate::extract_spki_from_cert_der(cert_der.as_ref())
        .ok_or_else(|| TlsError::PublicKeyExtraction(ERR_CERT_DER_PARSE.into()))
}

/// Adapter that implements rustls's internal `ServerCertVerifier` by
/// delegating to our public [`ServerCertVerifier`] trait.
///
/// rustls still does cryptographic signature verification; our verifier
/// only controls the trust decision for the peer's leaf certificate.
/// Signature verification uses the built-in rustls scheme so self-signed
/// certificates are handled safely even when [`AcceptAll`] is used.
struct VerifierBridge {
    user: Arc<dyn ServerCertVerifier>,
    // We delegate signature verification to the dangerous no-verify helper
    // which already implements `supported_verify_schemes()`. Our wrapper
    // only adds the user's trust decision on top.
    inner: DangerousNoVerify,
}

// `rustls::client::danger::ServerCertVerifier` requires `Debug`. We cannot
// derive it because `dyn ServerCertVerifier` has no `Debug` bound — intentionally,
// so that trust configuration does not accidentally leak through log formatting.
impl std::fmt::Debug for VerifierBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierBridge").finish_non_exhaustive()
    }
}

impl VerifierBridge {
    fn new(user: Arc<dyn ServerCertVerifier>) -> Self {
        Self {
            user,
            inner: DangerousNoVerify,
        }
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
    ) -> Result<ServerCertVerified, rustls::Error> {
        let sn = match server_name {
            ServerName::DnsName(dns) => dns.as_ref().to_string(),
            ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
            _ => String::new(),
        };
        match self.user.verify(end_entity.as_ref(), &sn) {
            CertDecision::Accept | CertDecision::AcceptOnce => Ok(ServerCertVerified::assertion()),
            CertDecision::Reject => Err(rustls::Error::General(ERR_CERT_REJECTED.into())),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rustls_upgrader_default_and_with_verify_both_construct() {
        let _no_verify = RustlsUpgrader::new();
        let _default = RustlsUpgrader::default();
        let _verify = RustlsUpgrader::with_verification();
    }

    #[test]
    fn rustls_upgrader_with_verifier_constructs() {
        let _custom = RustlsUpgrader::with_verifier(Arc::new(AcceptAll));
    }

    #[test]
    fn build_system_roots_config_has_no_alpn() {
        let config = build_system_roots_config();
        assert!(
            config.alpn_protocols.is_empty(),
            "no ALPN should be set by default"
        );
    }

    /// Mock verifier that records every call and returns Reject.
    struct RejectAll;
    impl ServerCertVerifier for RejectAll {
        fn verify(&self, _cert_der: &[u8], _server_name: &str) -> CertDecision {
            CertDecision::Reject
        }
    }

    #[test]
    fn verifier_bridge_forwards_reject_decision() {
        let bridge = VerifierBridge::new(Arc::new(RejectAll));

        let cert = CertificateDer::from(vec![0u8; 10]);
        let name = ServerName::try_from("example.com").unwrap();
        let result = bridge.verify_server_cert(&cert, &[], &name, &[], UnixTime::now());
        assert!(result.is_err(), "RejectAll must propagate to rustls Error");
    }

    #[test]
    fn verifier_bridge_forwards_accept_decision() {
        let bridge = VerifierBridge::new(Arc::new(AcceptAll));

        let cert = CertificateDer::from(vec![0u8; 10]);
        let name = ServerName::try_from("example.com").unwrap();
        let result = bridge.verify_server_cert(&cert, &[], &name, &[], UnixTime::now());
        assert!(result.is_ok(), "AcceptAll must produce a verified assertion");
    }

    /// Verifier that returns AcceptOnce for testing the semantic marker path.
    struct AcceptOnceVerifier;
    impl ServerCertVerifier for AcceptOnceVerifier {
        fn verify(&self, _cert_der: &[u8], _server_name: &str) -> CertDecision {
            CertDecision::AcceptOnce
        }
    }

    #[test]
    fn verifier_bridge_forwards_accept_once_decision() {
        let bridge = VerifierBridge::new(Arc::new(AcceptOnceVerifier));

        let cert = CertificateDer::from(vec![0u8; 10]);
        let name = ServerName::try_from("example.com").unwrap();
        let result = bridge.verify_server_cert(&cert, &[], &name, &[], UnixTime::now());
        assert!(result.is_ok(), "AcceptOnce must also produce a verified assertion");
    }

    #[test]
    fn verifier_bridge_supported_schemes_non_empty() {
        let bridge = VerifierBridge::new(Arc::new(AcceptAll));
        let schemes = bridge.supported_verify_schemes();
        assert!(!schemes.is_empty(), "must advertise at least one scheme");
        assert!(schemes.contains(&SignatureScheme::RSA_PKCS1_SHA256));
    }

    /// Recording verifier that captures the server_name it receives.
    struct RecordingVerifier {
        captured: std::sync::Mutex<Option<String>>,
    }
    impl RecordingVerifier {
        fn new() -> Self {
            Self { captured: std::sync::Mutex::new(None) }
        }
        fn captured_name(&self) -> String {
            self.captured.lock().unwrap().clone().unwrap()
        }
    }
    impl ServerCertVerifier for RecordingVerifier {
        fn verify(&self, _cert_der: &[u8], server_name: &str) -> CertDecision {
            *self.captured.lock().unwrap() = Some(server_name.to_string());
            CertDecision::Accept
        }
    }

    #[test]
    fn verifier_bridge_ip_address_format() {
        let recorder = Arc::new(RecordingVerifier::new());
        let bridge = VerifierBridge::new(Arc::clone(&recorder) as Arc<dyn ServerCertVerifier>);
        let cert = CertificateDer::from(vec![0u8; 10]);

        // IPv4 address must be passed as plain dotted-decimal, not Debug format
        let name = ServerName::try_from("192.168.1.1".to_string()).unwrap();
        let _ = bridge.verify_server_cert(&cert, &[], &name, &[], UnixTime::now());
        assert_eq!(recorder.captured_name(), "192.168.1.1",
            "IP address must be formatted as plain string, not Debug");
    }
}
