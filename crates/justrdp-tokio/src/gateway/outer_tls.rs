#![forbid(unsafe_code)]

//! Outer-TLS connect helper for the async gateway transport family.
//!
//! All three MS-TSGU transport variants (HTTP, WebSocket, RPC-over-HTTP)
//! start the same way:
//!
//! 1. Resolve the gateway address.
//! 2. Open a `tokio::net::TcpStream` (with a connect timeout).
//! 3. Run a TLS handshake against the gateway's certificate.
//!
//! The blocking equivalent inlines this prologue inside
//! `open_authenticated_channel`. Async pulls it out into a single
//! function because the HTTP variant calls it twice (once per
//! IN/OUT channel) and the RPCH variant calls it twice as well —
//! wrapping it here avoids three near-identical copies.
//!
//! This helper is intentionally generic over the user-supplied
//! [`TlsUpgrade`]: the embedder picks `NativeTlsUpgrade` (rustls)
//! or `NativeTlsOsUpgrade` (OS native-tls) per session, with the
//! gateway hostname / SNI baked into the upgrader at construction
//! time. The gateway code never inspects which backend is in use.

use alloc::format;

use justrdp_async::{TlsUpgrade, TransportError, WebTransport};
use tokio::net::ToSocketAddrs;
use tokio::time;

use crate::gateway::GatewayConfig;
use crate::native_tcp::NativeTcpTransport;

/// Open a TCP connection to the gateway and run the outer TLS
/// handshake using the supplied upgrader.
///
/// On success the returned transport is positioned at the very first
/// byte of the gateway's HTTP/1.1 server stream — ready for the
/// caller (G2+) to send the initial `RDG_*_DATA` request and start
/// the NTLM 401 retry loop.
///
/// # Timeouts
///
/// * The TCP connect is bounded by `cfg.connect_timeout`.
/// * The TLS handshake is bounded by `cfg.auth_timeout`.
///
/// Both timeouts surface as
/// [`TransportErrorKind::Io`](justrdp_async::TransportErrorKind::Io)
/// (matching how `tokio::time::timeout` reports elapsed deadlines —
/// not protocol-level failures).
//
// `allow(dead_code)` is silenced because the consumers of this helper
// land in the follow-up G2-G9 commits. The function is exercised by
// its own unit tests and committed first so the transport variants
// can stay focused on protocol logic.
#[allow(dead_code)]
pub(crate) async fn connect_outer_tls<U>(
    cfg: &GatewayConfig,
    upgrader: U,
) -> Result<U::Output, TransportError>
where
    U: TlsUpgrade<NativeTcpTransport, Error = TransportError>,
    U::Output: WebTransport,
{
    connect_outer_tls_addr(cfg, cfg.gateway_addr.as_str(), upgrader).await
}

/// Lower-level form of [`connect_outer_tls`] that takes the address
/// explicitly. Both helpers share a body; embedders / tests with a
/// pre-resolved `SocketAddr` can call this one directly.
#[allow(dead_code)]
pub(crate) async fn connect_outer_tls_addr<A, U>(
    cfg: &GatewayConfig,
    addr: A,
    upgrader: U,
) -> Result<U::Output, TransportError>
where
    A: ToSocketAddrs,
    U: TlsUpgrade<NativeTcpTransport, Error = TransportError>,
    U::Output: WebTransport,
{
    let tcp = time::timeout(cfg.connect_timeout, NativeTcpTransport::connect(addr))
        .await
        .map_err(|_| {
            TransportError::io(format!(
                "gateway: tcp connect timed out after {:?}",
                cfg.connect_timeout
            ))
        })??;

    let tls = time::timeout(cfg.auth_timeout, upgrader.upgrade(tcp))
        .await
        .map_err(|_| {
            TransportError::io(format!(
                "gateway: tls handshake timed out after {:?}",
                cfg.auth_timeout
            ))
        })??;

    Ok(tls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;
    use justrdp_async::{TransportError, TransportErrorKind};
    use justrdp_gateway::NtlmCredentials;
    use tokio::net::TcpListener;

    /// `TlsUpgrade` that succeeds without doing TLS — for asserting
    /// the outer connect path independent of any TLS backend.
    struct PassthroughUpgrade;

    impl TlsUpgrade<NativeTcpTransport> for PassthroughUpgrade {
        type Output = NativeTcpTransport;
        type Error = TransportError;

        async fn upgrade(self, t: NativeTcpTransport) -> Result<NativeTcpTransport, TransportError> {
            Ok(t)
        }
    }

    /// `TlsUpgrade` that hangs forever — used to drive the
    /// `auth_timeout` branch.
    struct StuckUpgrade;

    impl TlsUpgrade<NativeTcpTransport> for StuckUpgrade {
        type Output = NativeTcpTransport;
        type Error = TransportError;

        async fn upgrade(self, _t: NativeTcpTransport) -> Result<NativeTcpTransport, TransportError> {
            // Never resolves.
            core::future::pending::<()>().await;
            unreachable!()
        }
    }

    fn cfg(addr: alloc::string::String) -> GatewayConfig {
        let mut c = GatewayConfig::new(
            addr,
            "gw.example.com",
            NtlmCredentials::new("user", "pass", ""),
            "rdp.example.com",
        );
        c.connect_timeout = Duration::from_millis(200);
        c.auth_timeout = Duration::from_millis(200);
        c
    }

    #[tokio::test]
    async fn passthrough_upgrade_returns_connected_transport() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept on a side task so the connect can proceed.
        let _accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let cfg = cfg(format!("{addr}"));
        let mut t = connect_outer_tls(&cfg, PassthroughUpgrade).await.unwrap();
        // Sanity — the returned transport is alive enough to push an
        // empty send (which is a no-op per WebTransport contract).
        t.send(&[]).await.unwrap();
    }

    #[tokio::test]
    async fn connect_timeout_surfaces_as_io_kind() {
        // Use a non-routable address (TEST-NET-1, RFC 5737).
        let cfg = cfg(alloc::string::String::from("192.0.2.1:443"));
        let err = connect_outer_tls(&cfg, PassthroughUpgrade)
            .await
            .unwrap_err();
        // Either the kernel fails fast (refused / unreachable) or the
        // tokio timeout fires; both are Io-class.
        assert_eq!(err.kind(), TransportErrorKind::Io);
    }

    #[tokio::test]
    async fn tls_handshake_timeout_surfaces_as_io_kind() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let cfg = cfg(format!("{addr}"));
        let err = connect_outer_tls(&cfg, StuckUpgrade).await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Io);
    }
}
