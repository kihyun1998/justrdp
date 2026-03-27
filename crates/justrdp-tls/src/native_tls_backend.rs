#![forbid(unsafe_code)]

//! native-tls based TLS backend.

use std::io::{Read, Write};

use crate::{TlsError, TlsUpgradeResult, TlsUpgrader};

/// TLS upgrader using the `native-tls` library (platform TLS).
///
/// By default, this accepts self-signed certificates (common for RDP servers).
/// Set `verify_certificates` to `true` for strict certificate validation.
pub struct NativeTlsUpgrader {
    /// Whether to verify server certificates strictly.
    pub verify_certificates: bool,
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
            .map_err(|e| TlsError::Handshake(e.to_string()))?;

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
        .ok_or_else(|| TlsError::PublicKeyExtraction("failed to parse certificate DER".into()))
}

/// Trait alias for Read + Write.
pub trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}
