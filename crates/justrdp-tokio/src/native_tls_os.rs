#![forbid(unsafe_code)]

//! OS-native TLS upgrade via `tokio-native-tls`.
//!
//! Parallel to [`crate::native_tls`] (which uses `tokio-rustls`),
//! this module wires the OS-provided TLS stack into
//! [`justrdp_async::WebClient::connect_with_upgrade`]:
//!
//! * **Windows** — SChannel, the same stack that `mstsc.exe` uses.
//! * **macOS** — Secure Transport (with the system keychain).
//! * **Linux** — OpenSSL.
//!
//! Use this backend when the embedder needs to honour the OS trust
//! store, integrate with corporate-PKI client-cert smartcards, or
//! match a host's TLS posture (FIPS-mode SChannel, etc.). For most
//! self-signed RDP-server scenarios the rustls backend is fine and
//! avoids pulling OpenSSL on Linux.
//!
//! ```ignore
//! use justrdp_async::WebClient;
//! use justrdp_tokio::{NativeTcpTransport, NativeTlsOsUpgrade};
//!
//! let transport = NativeTcpTransport::connect(("rdp.example.com", 3389)).await?;
//! let upgrader = NativeTlsOsUpgrade::dangerous_no_verify("rdp.example.com")?;
//! WebClient::new(transport)
//!     .connect_with_upgrade(config, upgrader)
//!     .await?;
//! ```
//!
//! Two constructors mirror the rustls counterpart:
//!
//! * [`Self::dangerous_no_verify`] — accepts any server certificate
//!   (`danger_accept_invalid_certs` + `danger_accept_invalid_hostnames`).
//!   Matches the RDP default; CredSSP / NLA cross-checks the leaf SPKI.
//! * [`Self::with_os_trust_store`] — strict verification against the
//!   OS trust store. Use this for managed gateways with CA-signed certs.
//!
//! For full control build a `tokio_native_tls::TlsConnector` yourself
//! (typically by configuring a `native_tls::TlsConnector::builder()`)
//! and pass it via [`Self::from_connector`].

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use tokio::net::TcpStream;
use tokio_native_tls::native_tls;
use tokio_native_tls::{TlsConnector, TlsStream};

use justrdp_async::{TlsUpgrade, TransportError, WebTransport};

use crate::io_pipe::AsyncIoTransport;
use crate::native_tcp::NativeTcpTransport;

/// Async TLS upgrade backed by `tokio-native-tls` (OS TLS stack).
pub struct NativeTlsOsUpgrade {
    connector: TlsConnector,
    server_name: String,
}

impl core::fmt::Debug for NativeTlsOsUpgrade {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeTlsOsUpgrade")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl NativeTlsOsUpgrade {
    /// Build with a no-verify config — accepts any server certificate
    /// AND any hostname mismatch. Default for stock RDP servers (which
    /// usually present a self-signed cert with a name that doesn't
    /// match the address the embedder dialed).
    pub fn dangerous_no_verify(server_name: impl Into<String>) -> Result<Self, TransportError> {
        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .map_err(|e| TransportError::other(format!("native-tls builder: {e}")))?;
        Self::from_connector(TlsConnector::from(connector), server_name)
    }

    /// Build with strict OS trust store verification (default
    /// `native_tls::TlsConnector`). Rejects self-signed and untrusted
    /// chains.
    pub fn with_os_trust_store(server_name: impl Into<String>) -> Result<Self, TransportError> {
        let connector = native_tls::TlsConnector::builder()
            .build()
            .map_err(|e| TransportError::other(format!("native-tls builder: {e}")))?;
        Self::from_connector(TlsConnector::from(connector), server_name)
    }

    /// Build from a caller-supplied `tokio_native_tls::TlsConnector`.
    /// Use when the embedder needs full control over `native_tls::TlsConnectorBuilder`
    /// (client cert pinning, ALPN, min-version, FIPS-only providers, etc.).
    pub fn from_connector(
        connector: TlsConnector,
        server_name: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let server_name = server_name.into();
        if server_name.is_empty() {
            return Err(TransportError::protocol("empty server name"));
        }
        Ok(Self {
            connector,
            server_name,
        })
    }
}

impl TlsUpgrade<NativeTcpTransport> for NativeTlsOsUpgrade {
    type Output = NativeTlsOsTransport;
    type Error = TransportError;

    async fn upgrade(
        self,
        transport: NativeTcpTransport,
    ) -> Result<NativeTlsOsTransport, TransportError> {
        let tcp = transport.into_stream();
        let stream = self
            .connector
            .connect(&self.server_name, tcp)
            .await
            .map_err(|e| TransportError::io(format!("tls handshake: {e}")))?;
        Ok(NativeTlsOsTransport::from_stream(stream))
    }
}

/// Post-TLS transport — wraps `tokio_native_tls::TlsStream<TcpStream>`
/// the same way [`NativeTcpTransport`] wraps the raw socket.
pub struct NativeTlsOsTransport {
    inner: AsyncIoTransport<TlsStream<TcpStream>>,
}

impl core::fmt::Debug for NativeTlsOsTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeTlsOsTransport")
            .field("inner", &self.inner)
            .finish()
    }
}

impl NativeTlsOsTransport {
    /// Wrap an already-handshaken TLS stream — useful when the caller
    /// drove the handshake themselves and just wants to expose it as a
    /// [`WebTransport`].
    pub fn from_stream(stream: TlsStream<TcpStream>) -> Self {
        Self {
            inner: AsyncIoTransport::new(stream, "native-tls-os"),
        }
    }

    /// Override the per-`recv()` read buffer. Zero falls back to the
    /// default (16 KiB).
    pub fn set_recv_buf_size(&mut self, bytes: usize) {
        self.inner.set_recv_buf_size(bytes);
    }

    /// Extract the DER-encoded `SubjectPublicKeyInfo` of the server's
    /// leaf certificate. Used by [`crate::NativeCredsspDriver`] to drive
    /// the `pubKeyAuth` step of MS-CSSP §3.1.5.
    ///
    /// Returns `None` if no peer certificate was presented (vanishing
    /// rare for client-side connections to a real RDP server) or if the
    /// platform TLS stack didn't expose the certificate via
    /// `peer_certificate()`. Schannel, SecureTransport, and OpenSSL all
    /// expose it under normal conditions; the failure mode is
    /// resumed-session edge cases.
    pub fn server_public_key(&self) -> Option<Vec<u8>> {
        let cert = self
            .inner
            .stream()
            .get_ref()
            .peer_certificate()
            .ok()
            .flatten()?;
        let der = cert.to_der().ok()?;
        justrdp_tls::extract_spki_from_cert_der(&der)
    }
}

impl WebTransport for NativeTlsOsTransport {
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

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_async::TransportErrorKind;

    #[test]
    fn dangerous_no_verify_accepts_dns_server_name() {
        let upgrader = NativeTlsOsUpgrade::dangerous_no_verify("rdp.example.com");
        assert!(upgrader.is_ok());
    }

    #[test]
    fn dangerous_no_verify_accepts_ip_server_name() {
        // Unlike rustls's strict ServerName parsing, native-tls accepts
        // anything non-empty as the SNI hostname; verification mode is
        // configured separately. An IP literal must be accepted at the
        // upgrader-construction stage.
        let upgrader = NativeTlsOsUpgrade::dangerous_no_verify("192.168.1.1");
        assert!(upgrader.is_ok());
    }

    #[test]
    fn dangerous_no_verify_rejects_empty_server_name() {
        let err = NativeTlsOsUpgrade::dangerous_no_verify("").unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[test]
    fn with_os_trust_store_builds_default_connector() {
        // Sanity check: native_tls::TlsConnector::builder().build() is
        // expected to succeed on every supported platform without
        // additional setup.
        let upgrader = NativeTlsOsUpgrade::with_os_trust_store("rdp.example.com");
        assert!(upgrader.is_ok());
    }

    #[test]
    fn from_connector_rejects_empty_server_name() {
        let connector = TlsConnector::from(
            native_tls::TlsConnector::builder().build().unwrap(),
        );
        let err = NativeTlsOsUpgrade::from_connector(connector, "").unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }
}
