#![forbid(unsafe_code)]

//! End-to-end gateway connect entry point.
//!
//! Composes the four blocks built up across G1-G4:
//!
//! 1. [`connect_outer_tls`] — TCP + outer TLS to the gateway.
//! 2. [`authenticate_http_channel`] — three-step NTLM 401 retry on
//!    each of the IN / OUT channels.
//! 3. [`TsguHttpTransport::connect`] — drives the MS-TSGU
//!    Handshake / TunnelCreate / TunnelAuth / ChannelCreate state
//!    machine over the paired channels.
//! 4. [`WebClient::connect_with_upgrade`] — runs the inner RDP
//!    handshake (X.224 negotiation + inner TLS) on top of the tunnel,
//!    handing off a post-TLS [`WebTransport`] to
//!    [`ActiveSession::with_processors`].
//!
//! Mirrors `justrdp_blocking::RdpClient::connect_via_gateway_with_upgrader`
//! in scope and shape. Two intentional gaps relative to blocking, both
//! deliberately deferred to keep this entry surface narrow:
//!
//! * **No CredSSP / NLA path here.** Servers that require NLA surface
//!   as [`DriverError::NlaRequired`]. Embedders that need NLA over a
//!   gateway can compose the building blocks
//!   ([`WebTransportTlsTransport::server_public_key`] gives them the
//!   inner-server SPKI) — a convenience wrapper lands in a follow-up.
//! * **No automatic redirect / reconnect.** Per the §5.6.2 audit,
//!   redirect / reconnect are owned by the embedder. Through a
//!   gateway each retry would need a fresh tunnel anyway, so the
//!   embedder loop is the right shape.
//!
//! [`connect_outer_tls`]: super::outer_tls::connect_outer_tls
//! [`authenticate_http_channel`]: super::http_auth::authenticate_http_channel
//! [`TsguHttpTransport::connect`]: super::http_transport::TsguHttpTransport::connect
//! [`WebClient::connect_with_upgrade`]: justrdp_async::WebClient::connect_with_upgrade
//! [`ActiveSession::with_processors`]: justrdp_async::ActiveSession::with_processors
//! [`WebTransportTlsTransport::server_public_key`]: super::inner_tls::WebTransportTlsTransport::server_public_key
//! [`WebTransport`]: justrdp_async::WebTransport

use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;

use justrdp_async::{
    ActiveSession, DriverError, TlsUpgrade, TransportError, WebClient, WebTransport,
};
use justrdp_connector::ConnectionResult;
use justrdp_gateway::{GatewayClient, GatewayClientConfig, RdgMethod};
use justrdp_svc::SvcProcessor;

use super::config::GatewayConfig;
use super::http_auth::authenticate_http_channel;
use super::http_transport::TsguHttpTransport;
use super::outer_tls::connect_outer_tls;
use super::random::make_connection_id;
use crate::native_tcp::NativeTcpTransport;

/// Establish an RDP session through a Remote Desktop Gateway,
/// returning the post-handshake [`ConnectionResult`] and a live
/// [`ActiveSession`] driving the inner-TLS transport.
///
/// `make_outer` is called twice — once for the OUT channel, once
/// for the IN channel — because [`TlsUpgrade::upgrade`] consumes
/// `self`. Pass a closure that builds a fresh upgrader each call,
/// e.g. `|| NativeTlsUpgrade::dangerous_no_verify(host).unwrap()`.
///
/// `inner_upgrader` is the inner RDP TLS upgrader — typically
/// [`WebTransportTlsUpgrade`] — and is only consumed once
/// (`connect_with_upgrade` is one-shot).
///
/// `processors` are static virtual channel processors (clipboard,
/// drive redirection, sound, drdynvc, …); the same surface as
/// [`ActiveSession::with_processors`].
///
/// On any failure during the gateway tunnel setup the inner streams
/// are dropped — TCP-level cleanup happens via `Drop`. NTLM /
/// MS-TSGU rejections surface as [`DriverError::Transport`] (with
/// the underlying [`TransportError`] kind preserved).
///
/// [`WebTransportTlsUpgrade`]: super::inner_tls::WebTransportTlsUpgrade
pub async fn connect_via_gateway<MakeOuter, Outer, Inner>(
    gateway_cfg: &GatewayConfig,
    rdp_config: justrdp_connector::Config,
    mut make_outer: MakeOuter,
    inner_upgrader: Inner,
    processors: Vec<Box<dyn SvcProcessor>>,
) -> Result<(ConnectionResult, ActiveSession<Inner::Output>), DriverError>
where
    MakeOuter: FnMut() -> Outer,
    Outer: TlsUpgrade<NativeTcpTransport, Error = TransportError>,
    Outer::Output: WebTransport + Send + 'static,
    Inner: TlsUpgrade<TsguHttpTransport<Outer::Output>>,
    Inner::Output: WebTransport + Send + 'static,
{
    // 1. Connection-id: one GUID shared by both channels per
    //    MS-TSGU §3.3.5.1.
    let connection_id = match gateway_cfg.connection_id {
        Some(id) => id,
        None => make_connection_id().map_err(DriverError::Transport)?,
    };

    // 2. OUT channel — opened first so the 100-byte preamble is
    //    visible before the IN channel starts emitting PDUs.
    let mut out_chan = connect_outer_tls(gateway_cfg, make_outer())
        .await
        .map_err(DriverError::Transport)?;
    let out_leftover = authenticate_http_channel(
        &mut out_chan,
        RdgMethod::OutData,
        gateway_cfg,
        connection_id,
    )
    .await
    .map_err(DriverError::Transport)?;

    // 3. IN channel.
    let mut in_chan = connect_outer_tls(gateway_cfg, make_outer())
        .await
        .map_err(DriverError::Transport)?;
    let _in_leftover = authenticate_http_channel(
        &mut in_chan,
        RdgMethod::InData,
        gateway_cfg,
        connection_id,
    )
    .await
    .map_err(DriverError::Transport)?;

    // 4. MS-TSGU tunnel.
    let gw_client = GatewayClient::new(GatewayClientConfig {
        target_host: gateway_cfg.target_host.clone(),
        target_port: gateway_cfg.target_port,
        client_name: gateway_cfg.gateway_hostname.clone(),
        client_caps: GatewayClientConfig::default_caps(),
        paa_cookie: None,
    });
    let tunnel = TsguHttpTransport::connect(gw_client, in_chan, out_chan, out_leftover)
        .await
        .map_err(DriverError::Transport)?;

    // 5. Inner RDP handshake on top of the tunnel. The connector
    //    drives X.224 → enhanced security → BasicSettings →
    //    Finalization, with the inner_upgrader running the inner
    //    TLS handshake mid-flow.
    let client = WebClient::new(tunnel);
    let (result, post_tls) = client
        .connect_with_upgrade(rdp_config, inner_upgrader)
        .await?;

    // 6. Refuse server-side redirection — through a gateway, the
    //    target address in the redirect is unreachable directly,
    //    and re-tunneling requires a fresh authenticated channel
    //    pair plus a separate retry policy that the embedder must
    //    own. Same boundary as blocking's
    //    `run_handshake_over_tunnel`.
    if result.server_redirection.is_some() {
        return Err(DriverError::Internal(format!(
            "gateway path: server redirection is not supported \
             (the target address in a redirect is unreachable through the same tunnel)"
        )));
    }

    // 7. ActiveSession with caller-supplied SVC processors. Mirrors
    //    `RdpClient::connect_with_processors` ergonomics — same
    //    surface, async drain.
    let session = ActiveSession::with_processors(post_tls, &result, processors).await?;
    Ok((result, session))
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_async::TransportErrorKind;
    use justrdp_gateway::NtlmCredentials;

    /// Failing-outer-upgrader smoke test — the entry point must
    /// surface the upgrader's error as `DriverError::Transport`
    /// rather than panicking. Exercises the OUT-channel path; we
    /// don't go further because making the rest of the handshake
    /// pass requires a real gateway.
    struct FailingUpgrade;
    impl TlsUpgrade<NativeTcpTransport> for FailingUpgrade {
        type Output = NativeTcpTransport;
        type Error = TransportError;
        async fn upgrade(self, _: NativeTcpTransport) -> Result<NativeTcpTransport, TransportError> {
            Err(TransportError::protocol("test: upgrade refused"))
        }
    }

    fn cfg(addr: &str) -> GatewayConfig {
        let mut c = GatewayConfig::new(
            addr,
            "gw.example.com",
            NtlmCredentials::new("alice", "hunter2", ""),
            "rdp.example.com",
        );
        c.connect_timeout = core::time::Duration::from_millis(200);
        c.auth_timeout = core::time::Duration::from_millis(200);
        c
    }

    #[tokio::test]
    async fn outer_upgrade_failure_surfaces_as_driver_transport_error() {
        // Bind a loopback listener so the TCP connect succeeds; the
        // outer upgrader then refuses, exiting before any auth I/O.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Drain accepts on a side task — they immediately drop the
        // accepted socket which is fine because the upgrader fails
        // before the test client writes anything.
        let _accept = tokio::spawn(async move {
            for _ in 0..2 {
                let _ = listener.accept().await;
            }
        });

        let gw_cfg = cfg(&format!("{addr}"));
        let rdp_cfg = justrdp_connector::Config::builder("alice", "p4ss").build();

        // Inner upgrader is unreachable here — the outer-side fails
        // first — so any value satisfying the trait works.
        let inner = super::super::inner_tls::WebTransportTlsUpgrade::dangerous_no_verify(
            "rdp.example.com",
        )
        .unwrap();

        let result = connect_via_gateway(
            &gw_cfg,
            rdp_cfg,
            || FailingUpgrade,
            inner,
            Vec::new(),
        )
        .await;

        match result {
            Err(DriverError::Transport(t)) => {
                assert_eq!(t.kind(), TransportErrorKind::Protocol);
            }
            Err(other) => panic!("expected Transport(Protocol), got {other:?}"),
            Ok(_) => panic!("expected error from FailingUpgrade, got Ok"),
        }
    }
}
