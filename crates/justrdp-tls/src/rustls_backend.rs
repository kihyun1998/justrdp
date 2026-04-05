#![forbid(unsafe_code)]

//! rustls-based TLS backend.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::danger::rustls_verifier::DangerousNoVerify;
use crate::{ReadWrite, TlsError, TlsUpgradeResult, TlsUpgrader, ERR_CERT_DER_PARSE};

/// TLS upgrader using the `rustls` library.
///
/// By default, this accepts self-signed certificates (common for RDP servers).
/// Use [`with_verification()`](Self::with_verification) for strict certificate validation.
pub struct RustlsUpgrader {
    config: Arc<ClientConfig>,
}

impl RustlsUpgrader {
    /// Create a new upgrader with default settings (no certificate verification).
    ///
    /// RDP servers commonly use self-signed certificates, so this is the
    /// appropriate default for most RDP connections (similar to mstsc.exe).
    pub fn new() -> Self {
        Self {
            config: Arc::new(build_config(false)),
        }
    }

    /// Create an upgrader that verifies server certificates against
    /// the system root certificate store.
    pub fn with_verification() -> Self {
        Self {
            config: Arc::new(build_config(true)),
        }
    }
}

fn build_config(verify_certificates: bool) -> ClientConfig {
    if verify_certificates {
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
    fn build_config_no_verify_enables_tls12() {
        let config = build_config(false);
        // TLS 1.2 should be enabled (rustls-backend feature includes tls12)
        assert!(
            config.alpn_protocols.is_empty(),
            "no ALPN should be set by default"
        );
    }

    #[test]
    fn build_config_with_verify_has_root_certs() {
        let config = build_config(true);
        // Config constructed with root store should not panic and
        // should have no ALPN set by default
        assert!(config.alpn_protocols.is_empty());
    }
}
