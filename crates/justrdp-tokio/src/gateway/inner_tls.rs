#![forbid(unsafe_code)]

//! Inner-TLS upgrader for nested TLS over a [`WebTransport`].
//!
//! When connecting to an RDP server through an MS-TSGU gateway, the
//! byte stream is already wrapped in:
//!
//! 1. An outer TLS session (`NativeTcpTransport` → `NativeTlsTransport`,
//!    handshaken against the gateway's certificate).
//! 2. The MS-TSGU framing layer ([`TsguHttpTransport`]).
//!
//! On top of that we still need a *second* TLS handshake with the
//! actual RDP server's certificate so the connector layer can run
//! its CredSSP / NLA / RDSTLS step on a stream that the connector
//! trusts end-to-end. That's what [`WebTransportTlsUpgrade`] does.
//!
//! Internally it uses [`WebTransportRw`](super::web_rw::WebTransportRw)
//! to expose the inner [`WebTransport`] as `AsyncRead + AsyncWrite`,
//! hands the result to [`tokio_rustls::TlsConnector::connect`], then
//! re-wraps the post-handshake `TlsStream` back into a
//! [`WebTransport`] via [`WebTransportTlsTransport`] so the rest of
//! the pump is unchanged.
//!
//! [`TsguHttpTransport`]: super::http_transport::TsguHttpTransport

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_async::{TlsServerSpki, TlsUpgrade, TransportError, WebTransport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

use super::web_rw::WebTransportRw;

/// Default per-`recv()` read buffer for the post-TLS transport.
/// Mirrors `NativeTlsTransport`'s default so tuning patterns match.
const DEFAULT_RECV_BUF_BYTES: usize = 16 * 1024;

/// rustls-based TLS upgrader generic over any inner [`WebTransport`].
///
/// Construct with the same constructors as
/// [`NativeTlsUpgrade`](crate::NativeTlsUpgrade) — the two upgraders
/// share their rustls config shape:
///
/// * [`Self::dangerous_no_verify`] — accepts any server certificate
///   (the RDP default; servers commonly use self-signed certs).
///   CredSSP / NLA cross-checks the leaf SPKI separately.
/// * [`Self::from_connector`] — caller-supplied
///   `tokio_rustls::TlsConnector` for full control of the rustls
///   config (custom verifier, pinned SPKI, ALPN, …).
pub struct WebTransportTlsUpgrade {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl core::fmt::Debug for WebTransportTlsUpgrade {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebTransportTlsUpgrade")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl WebTransportTlsUpgrade {
    /// Build with a no-verify config — accepts any server certificate.
    /// Same default as the rest of the stack: RDP servers typically
    /// present self-signed certs and the post-CredSSP SPKI cross-check
    /// is the real defense against MITM.
    pub fn dangerous_no_verify(server_name: impl Into<String>) -> Result<Self, TransportError> {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        Self::from_connector(TlsConnector::from(Arc::new(config)), server_name)
    }

    /// Build from a caller-supplied [`TlsConnector`]. Use when the
    /// embedder needs full control of the rustls config (custom
    /// verifier, pinned SPKI via `justrdp-tls::PinnedSpki` adapter,
    /// ALPN, …).
    pub fn from_connector(
        connector: TlsConnector,
        server_name: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let raw = server_name.into();
        let server_name = ServerName::try_from(raw.clone())
            .map_err(|e| TransportError::protocol(format!("invalid server name {raw}: {e}")))?
            .to_owned();
        Ok(Self {
            connector,
            server_name,
        })
    }
}

impl<X> TlsUpgrade<X> for WebTransportTlsUpgrade
where
    X: WebTransport + Send + 'static,
{
    type Output = WebTransportTlsTransport<X>;
    type Error = TransportError;

    async fn upgrade(self, transport: X) -> Result<Self::Output, TransportError> {
        let rw = WebTransportRw::new(transport);
        let stream = self
            .connector
            .connect(self.server_name, rw)
            .await
            .map_err(|e| TransportError::io(format!("inner tls handshake: {e}")))?;
        Ok(WebTransportTlsTransport::from_stream(stream))
    }
}

/// Post-TLS transport — wraps `TlsStream<WebTransportRw<X>>` in a
/// [`WebTransport`] surface so the connector / `WebClient` layer
/// above it carries on unaffected.
pub struct WebTransportTlsTransport<X: WebTransport + Send + 'static> {
    stream: TlsStream<WebTransportRw<X>>,
    recv_buf: Vec<u8>,
    closed: bool,
}

impl<X: WebTransport + Send + 'static> core::fmt::Debug for WebTransportTlsTransport<X> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebTransportTlsTransport")
            .field("recv_buf_capacity", &self.recv_buf.len())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl<X: WebTransport + Send + 'static> WebTransportTlsTransport<X> {
    /// Wrap an already-handshaken TLS stream. Use when the embedder
    /// drove the handshake via their own `TlsConnector` and wants to
    /// hand off the result.
    pub fn from_stream(stream: TlsStream<WebTransportRw<X>>) -> Self {
        Self {
            stream,
            recv_buf: vec![0u8; DEFAULT_RECV_BUF_BYTES],
            closed: false,
        }
    }

    /// Override the per-`recv()` read buffer. Zero means default.
    pub fn set_recv_buf_size(&mut self, bytes: usize) {
        let new_size = if bytes == 0 {
            DEFAULT_RECV_BUF_BYTES
        } else {
            bytes
        };
        self.recv_buf = vec![0u8; new_size];
    }

    /// Extract the DER-encoded `SubjectPublicKeyInfo` of the inner
    /// server's leaf certificate. Used by CredSSP / NLA to drive
    /// the `pubKeyAuth` step of MS-CSSP §3.1.5 against the *inner*
    /// (RDP server) certificate, not the gateway's.
    pub fn server_public_key(&self) -> Option<Vec<u8>> {
        let (_io, conn) = self.stream.get_ref();
        let certs = conn.peer_certificates()?;
        let leaf = certs.first()?;
        justrdp_tls::extract_spki_from_cert_der(leaf.as_ref())
    }
}

impl<X: WebTransport + Send + 'static> WebTransport for WebTransportTlsTransport<X> {
    async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::closed("inner-tls: already closed"));
        }
        if bytes.is_empty() {
            return Ok(());
        }
        self.stream
            .write_all(bytes)
            .await
            .map_err(|e| TransportError::io(format!("inner tls send: {e}")))?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.closed {
            return Err(TransportError::closed("inner-tls: already closed"));
        }
        let n = self
            .stream
            .read(&mut self.recv_buf)
            .await
            .map_err(|e| TransportError::io(format!("inner tls recv: {e}")))?;
        if n == 0 {
            self.closed = true;
            return Err(TransportError::closed("inner-tls: peer closed"));
        }
        Ok(self.recv_buf[..n].to_vec())
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        if let Err(e) = self.stream.shutdown().await {
            return Err(TransportError::io(format!("inner tls shutdown: {e}")));
        }
        Ok(())
    }
}

impl<X: WebTransport + Send + 'static> TlsServerSpki for WebTransportTlsTransport<X> {
    fn server_public_key(&self) -> Option<Vec<u8>> {
        // Delegate to the inherent method so external callers using
        // `transport.server_public_key()` keep compiling without the
        // trait imported (Rust resolves inherent methods first).
        Self::server_public_key(self)
    }
}

/// rustls verifier that accepts any server certificate.
///
/// Identical to the verifier inside `NativeTlsUpgrade`; duplicated
/// here so each module owns its own private verifier and the two
/// can diverge if one ever needs a custom rule (pinned SPKI for the
/// inner cert, etc.) without affecting the other.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
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
        vec![
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
    use justrdp_async::TransportErrorKind;

    #[test]
    fn dangerous_no_verify_accepts_dns_server_name() {
        let upgrader = WebTransportTlsUpgrade::dangerous_no_verify("rdp.example.com");
        assert!(upgrader.is_ok());
    }

    #[test]
    fn dangerous_no_verify_accepts_ip_server_name() {
        let upgrader = WebTransportTlsUpgrade::dangerous_no_verify("192.168.1.1");
        assert!(upgrader.is_ok());
    }

    #[test]
    fn dangerous_no_verify_rejects_invalid_server_name() {
        let err =
            WebTransportTlsUpgrade::dangerous_no_verify("not a valid host").unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[test]
    fn no_verify_supported_schemes_covers_rdp_common_cases() {
        let schemes = NoVerify.supported_verify_schemes();
        assert!(schemes.contains(&SignatureScheme::RSA_PKCS1_SHA256));
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
    }

    /// Sanity check the static type — `WebTransportTlsUpgrade` MUST
    /// satisfy `TlsUpgrade<X>` for any `X: WebTransport + Send +
    /// 'static`. A failing impl resolution would otherwise only
    /// surface inside the eventual `connect_via_gateway` entry
    /// point (G5).
    #[test]
    fn upgrader_implements_tls_upgrade_for_arbitrary_web_transport() {
        // Just a compile-time check: nothing actually runs.
        fn _check<X: WebTransport + Send + 'static>(_: WebTransportTlsUpgrade)
        where
            WebTransportTlsUpgrade: TlsUpgrade<X>,
        {
        }
    }
}
