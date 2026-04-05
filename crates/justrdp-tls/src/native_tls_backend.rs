#![forbid(unsafe_code)]

//! native-tls based TLS backend.

use std::io::{Read, Write};

use crate::{ReadWrite, TlsError, TlsUpgradeResult, TlsUpgrader, ERR_CERT_DER_PARSE};

/// TLS upgrader using the `native-tls` library (platform TLS).
///
/// By default, this accepts self-signed certificates (common for RDP servers).
/// Use [`with_verification()`](Self::with_verification) for strict certificate validation.
pub struct NativeTlsUpgrader {
    verify_certificates: bool,
}

impl NativeTlsUpgrader {
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

        if !self.verify_certificates {
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
                native_tls::HandshakeError::WouldBlock(_) => {
                    TlsError::Handshake("handshake would block (non-blocking stream not supported)".into())
                }
            })?;

        // Extract server public key from peer certificate
        let server_public_key = extract_native_tls_public_key(&tls_stream)?;

        Ok(TlsUpgradeResult {
            stream: tls_stream,
            server_public_key,
        })
    }
}

fn extract_native_tls_public_key(
    tls_stream: &native_tls::TlsStream<Box<dyn ReadWrite>>,
) -> Result<Vec<u8>, TlsError> {
    let cert = tls_stream
        .peer_certificate()
        .map_err(|e| TlsError::PublicKeyExtraction(e.to_string()))?
        .ok_or(TlsError::NoPeerCertificate)?;

    let der = cert.to_der().map_err(|e| {
        TlsError::PublicKeyExtraction(format!("failed to get DER: {e}"))
    })?;

    crate::extract_spki_from_cert_der(&der)
        .ok_or_else(|| TlsError::PublicKeyExtraction(ERR_CERT_DER_PARSE.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_tls_upgrader_default_no_verify() {
        let upgrader = NativeTlsUpgrader::new();
        assert!(!upgrader.verify_certificates);
    }

    #[test]
    fn native_tls_upgrader_with_verify() {
        let upgrader = NativeTlsUpgrader::with_verification();
        assert!(upgrader.verify_certificates);
    }

    #[test]
    fn native_tls_upgrader_default_trait() {
        let upgrader = NativeTlsUpgrader::default();
        assert!(!upgrader.verify_certificates);
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

