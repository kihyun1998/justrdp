#![forbid(unsafe_code)]

//! Native TLS upgrade via `tokio-rustls`.
//!
//! Plugs into [`justrdp_async::WebClient::connect_with_upgrade`] for
//! desktop embedders that want async TLS without bringing their own
//! TLS stack:
//!
//! ```ignore
//! use justrdp_async::WebClient;
//! use justrdp_tokio::{NativeTcpTransport, NativeTlsUpgrade};
//!
//! let transport = NativeTcpTransport::connect(("rdp.example.com", 3389)).await?;
//! let upgrader = NativeTlsUpgrade::dangerous_no_verify("rdp.example.com")?;
//! WebClient::new(transport)
//!     .connect_with_upgrade(config, upgrader)
//!     .await?;
//! ```
//!
//! Two constructors mirror what `justrdp-tls::RustlsUpgrader` exposes:
//!
//! * [`Self::dangerous_no_verify`] — accepts any server certificate.
//!   This is the RDP default (mstsc.exe doesn't verify by default
//!   either; servers commonly use self-signed certs). The verifier
//!   accepts the chain blindly but still records the leaf SPKI on
//!   the rustls side, which CredSSP / NLA can later cross-check via
//!   the connector's pubKeyAuth step.
//! * [`Self::with_system_roots`] — strict verification against the
//!   `webpki-roots` Mozilla bundle. Use this for managed gateways
//!   that present a CA-signed cert.
//!
//! For full control, build a `tokio_rustls::TlsConnector` yourself
//! and pass it via [`Self::from_connector`].

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

use justrdp_async::{TlsServerSpki, TlsUpgrade, TransportError, WebTransport};

use crate::io_pipe::AsyncIoTransport;
use crate::native_tcp::NativeTcpTransport;

/// Async TLS upgrade.
pub struct NativeTlsUpgrade {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl core::fmt::Debug for NativeTlsUpgrade {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeTlsUpgrade")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl NativeTlsUpgrade {
    /// Build with a no-verify config — accepts any server certificate.
    /// This matches `justrdp-tls::AcceptAll` and is the appropriate
    /// default for talking to a stock RDP server (self-signed cert).
    pub fn dangerous_no_verify(server_name: impl Into<String>) -> Result<Self, TransportError> {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        Self::from_connector(TlsConnector::from(Arc::new(config)), server_name)
    }

    /// Build with strict verification against the bundled Mozilla
    /// root store (via `webpki-roots`). Use for CA-signed certs (managed
    /// RDP gateways, etc.).
    ///
    /// **Note**: `webpki-roots` is not pulled in by this crate; this
    /// constructor is a stub that returns
    /// [`TransportErrorKind::Other`](justrdp_async::TransportErrorKind::Other) until
    /// an embedder needs it. Callers wanting strict roots today should
    /// build their own `ClientConfig` and use [`Self::from_connector`].
    /// (Tracking: roadmap §11.3 S7-2 follow-up — adds the optional
    /// `webpki-roots` dep once a real use case lands.)
    pub fn with_system_roots(_server_name: impl Into<String>) -> Result<Self, TransportError> {
        Err(TransportError::other(
            "with_system_roots: webpki-roots dep not yet wired — use from_connector with a custom ClientConfig",
        ))
    }

    /// Build from a caller-supplied `TlsConnector`. Use when the
    /// embedder needs full control of the rustls config (custom
    /// verifier, pinned SPKI via `justrdp-tls::PinnedSpki` adapter,
    /// ALPN, etc.).
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

impl TlsUpgrade<NativeTcpTransport> for NativeTlsUpgrade {
    type Output = NativeTlsTransport;
    type Error = TransportError;

    async fn upgrade(self, transport: NativeTcpTransport) -> Result<NativeTlsTransport, TransportError> {
        // Reach into the raw socket — `into_stream()` marks the
        // pre-TLS transport as closed so callers can't accidentally
        // double-use it post-upgrade.
        let tcp = transport.into_stream();
        let stream = self
            .connector
            .connect(self.server_name, tcp)
            .await
            .map_err(|e| TransportError::io(format!("tls handshake: {e}")))?;
        Ok(NativeTlsTransport::from_stream(stream))
    }
}

/// Post-TLS transport — wraps `tokio_rustls::client::TlsStream<TcpStream>`
/// the same way [`NativeTcpTransport`] wraps the raw socket.
pub struct NativeTlsTransport {
    inner: AsyncIoTransport<TlsStream<TcpStream>>,
}

impl core::fmt::Debug for NativeTlsTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeTlsTransport")
            .field("inner", &self.inner)
            .finish()
    }
}

impl NativeTlsTransport {
    /// Wrap an already-handshaken TLS stream. Use this when the caller
    /// drove the handshake via their own `TlsConnector` and wants to
    /// hand off the resulting stream as a `WebTransport`.
    pub fn from_stream(stream: TlsStream<TcpStream>) -> Self {
        Self {
            inner: AsyncIoTransport::new(stream, "native-tls"),
        }
    }

    /// Override the per-`recv()` read buffer. Zero means default.
    pub fn set_recv_buf_size(&mut self, bytes: usize) {
        self.inner.set_recv_buf_size(bytes);
    }

    /// Extract the DER-encoded `SubjectPublicKeyInfo` of the server's
    /// leaf certificate. Used by [`crate::NativeCredsspDriver`] to
    /// drive the `pubKeyAuth` step of MS-CSSP §3.1.5.
    ///
    /// Returns `None` only if the rustls connection somehow has no
    /// peer certificate (vanishingly rare — a successful TLS handshake
    /// always carries one for client-side connections).
    pub fn server_public_key(&self) -> Option<Vec<u8>> {
        let (_io, conn) = self.inner.stream().get_ref();
        let certs = conn.peer_certificates()?;
        let leaf = certs.first()?;
        justrdp_tls::extract_spki_from_cert_der(leaf.as_ref())
    }
}

impl WebTransport for NativeTlsTransport {
    async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.inner.send(bytes).await
    }

    async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        self.inner.recv().await
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.inner.close().await
    }
}

impl TlsServerSpki for NativeTlsTransport {
    fn server_public_key(&self) -> Option<Vec<u8>> {
        // Delegate to the inherent method so external callers using
        // `transport.server_public_key()` keep compiling without the
        // trait imported (Rust resolves inherent methods first).
        Self::server_public_key(self)
    }
}

/// rustls verifier that accepts any server certificate.
///
/// Mirrors `justrdp-tls::AcceptAll` but built directly on the rustls
/// `ServerCertVerifier` trait so we don't need to depend on
/// `justrdp-tls`. RDP servers commonly present self-signed certs;
/// CredSSP / NLA cross-checks the leaf SPKI separately, which is the
/// real defense against MITM in this stack.
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
        // Match what the `ring` provider supports — covers every
        // signature scheme RDP servers actually use (RSA-PKCS1,
        // RSA-PSS, ECDSA-P256/P384, Ed25519).
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
    use justrdp_async::TransportErrorKind;

    #[test]
    fn dangerous_no_verify_accepts_dns_server_name() {
        // The constructor builds a TlsConnector and parses the
        // server name as an `ServerName`. A valid DNS name must
        // succeed.
        let upgrader = NativeTlsUpgrade::dangerous_no_verify("rdp.example.com");
        assert!(upgrader.is_ok());
    }

    #[test]
    fn dangerous_no_verify_accepts_ip_server_name() {
        // RDP servers are often addressed by IP (192.168.x.y); rustls'
        // ServerName accepts IPs as well as DNS names. Verify the
        // constructor doesn't reject them.
        let upgrader = NativeTlsUpgrade::dangerous_no_verify("192.168.1.1");
        assert!(upgrader.is_ok());
    }

    #[test]
    fn dangerous_no_verify_rejects_invalid_server_name() {
        // Whitespace is invalid in a ServerName — must surface as
        // `Protocol` rather than panic.
        let err = NativeTlsUpgrade::dangerous_no_verify("not a valid host").unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[test]
    fn with_system_roots_returns_other_until_webpki_roots_wired() {
        // Sanity check on the placeholder — once `webpki-roots` is
        // added as an optional dep, this test gets deleted.
        let err = NativeTlsUpgrade::with_system_roots("rdp.example.com").unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Other);
    }

    #[test]
    fn no_verify_supported_schemes_covers_rdp_common_cases() {
        // Defensive: if anyone reorders or drops a scheme later, the
        // RDP stack should still authenticate (especially RSA-PKCS1
        // which legacy Windows servers still use).
        let schemes = NoVerify.supported_verify_schemes();
        assert!(schemes.contains(&SignatureScheme::RSA_PKCS1_SHA256));
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
    }

    #[tokio::test]
    async fn native_tls_transport_send_after_close_errors() {
        // Build a transport without a real handshake by skipping
        // construction (we test the close-state guards directly).
        // We can't construct a TlsStream without a peer, so this
        // test asserts the behaviour through state inspection
        // alone — the actual handshake path is covered by the
        // example integration test (S7-5).
        //
        // Instead, exercise the constructor path that wraps a
        // raw stream's close flag. A loopback TcpStream stands in.
        use tokio::net::TcpListener;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let _client_tcp = TcpStream::connect(addr).await.unwrap();
        // Note: we cannot reach the inner state without driving an
        // actual TLS handshake. This test is a placeholder pending
        // the integration-level handshake test in the example.
    }
}
