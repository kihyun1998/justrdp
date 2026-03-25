#![forbid(unsafe_code)]

//! rustls-based TLS backend.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::danger::rustls_verifier::DangerousNoVerify;
use crate::{TlsError, TlsUpgradeResult, TlsUpgrader};

/// TLS upgrader using the `rustls` library.
///
/// By default, this accepts self-signed certificates (common for RDP servers).
/// Set `verify_certificates` to `true` for strict certificate validation.
pub struct RustlsUpgrader {
    /// Whether to verify server certificates strictly.
    /// Default: `false` (accept self-signed certs like mstsc.exe).
    pub verify_certificates: bool,
}

impl RustlsUpgrader {
    /// Create a new upgrader with default settings (no certificate verification).
    pub fn new() -> Self {
        Self {
            verify_certificates: false,
        }
    }

    /// Create an upgrader that verifies server certificates.
    pub fn with_verification() -> Self {
        Self {
            verify_certificates: true,
        }
    }

    fn build_config(&self) -> ClientConfig {
        if self.verify_certificates {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerousNoVerify))
                .with_no_client_auth()
        }
    }
}

impl Default for RustlsUpgrader {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsUpgrader for RustlsUpgrader {
    type Stream = StreamOwned<ClientConnection, Box<dyn ReadWrite>>;

    fn upgrade<S: Read + Write + 'static>(
        &self,
        stream: S,
        server_name: &str,
    ) -> Result<TlsUpgradeResult<Self::Stream>, TlsError> {
        let config = Arc::new(self.build_config());

        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|e| TlsError::Handshake(format!("invalid server name: {e}")))?;

        let conn = ClientConnection::new(config, server_name)
            .map_err(|e| TlsError::Handshake(e.to_string()))?;

        // Box the stream so we have a single concrete type
        let boxed_stream: Box<dyn ReadWrite> = Box::new(stream);
        let mut tls_stream = StreamOwned::new(conn, boxed_stream);

        // Drive the handshake to completion
        let _ = tls_stream.flush();

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
        .ok_or_else(|| TlsError::PublicKeyExtraction("failed to parse certificate DER".into()))
}

/// Trait alias for Read + Write, needed for boxing.
pub trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rustls_upgrader_default_no_verify() {
        let upgrader = RustlsUpgrader::new();
        assert!(!upgrader.verify_certificates);
    }

    #[test]
    fn rustls_upgrader_with_verify() {
        let upgrader = RustlsUpgrader::with_verification();
        assert!(upgrader.verify_certificates);
    }

    #[test]
    fn build_config_no_verify() {
        let upgrader = RustlsUpgrader::new();
        let _config = upgrader.build_config();
        // Should not panic
    }

    #[test]
    fn build_config_with_verify() {
        let upgrader = RustlsUpgrader::with_verification();
        let _config = upgrader.build_config();
        // Should not panic
    }
}
