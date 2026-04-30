#![forbid(unsafe_code)]

//! Async-side mirror of `justrdp_blocking::gateway::GatewayConfig`.
//!
//! Identical field layout — the only difference is that timeouts are
//! interpreted by `tokio::time::timeout(...)` instead of being applied
//! to the underlying socket via `set_{read,write}_timeout`.

use alloc::string::String;
use core::time::Duration;

use justrdp_gateway::NtlmCredentials;

/// Configuration for reaching an RDP server through a Remote Desktop
/// Gateway from async code.
///
/// Mirrors `justrdp_blocking::gateway::GatewayConfig` field-for-field,
/// so a config built for the blocking client can be lifted to async by
/// `From<&blocking::GatewayConfig>` if needed (deferred — embedders
/// usually own the config and pass it to whichever stack they're
/// using).
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Gateway endpoint — e.g. `"gw.example.com:443"`. Resolved via
    /// `tokio::net::TcpStream::connect` when opening each channel; the
    /// embedder can pre-resolve and pass `"a.b.c.d:443"` instead if
    /// they want explicit control.
    pub gateway_addr: String,
    /// Hostname used for SNI, the `Host:` header, and gateway virtual
    /// host matching. Usually matches the SAN on the gateway's TLS
    /// certificate.
    pub gateway_hostname: String,
    /// Gateway credentials. Empty `domain` triggers the server's
    /// `MsvAvNbDomainName` fallback per MS-NLMP §3.1.5.1.2.
    pub credentials: NtlmCredentials,
    /// Target RDP server hostname — advertised inside the
    /// `HTTP_CHANNEL_PACKET.pResource` list (MS-TSGU §2.2.10.5).
    pub target_host: String,
    /// Target RDP server TCP port (typically `3389`).
    pub target_port: u16,
    /// TCP connect timeout for each gateway channel.
    pub connect_timeout: Duration,
    /// Per-round timeout used to bound each authentication / handshake
    /// round-trip (TLS handshake + each NTLM 401 retry).
    pub auth_timeout: Duration,
    /// Optional 16-byte `RDG-Connection-Id` GUID. If `None`, a fresh
    /// value is generated from the OS RNG and used for both channels
    /// (they MUST share the same GUID per §3.3.5.1).
    pub connection_id: Option<[u8; 16]>,
}

impl GatewayConfig {
    /// Build a config with the four mandatory fields. Defaults match
    /// the blocking equivalent so embedders can swap stacks without
    /// re-tuning timeouts.
    pub fn new(
        gateway_addr: impl Into<String>,
        gateway_hostname: impl Into<String>,
        credentials: NtlmCredentials,
        target_host: impl Into<String>,
    ) -> Self {
        Self {
            gateway_addr: gateway_addr.into(),
            gateway_hostname: gateway_hostname.into(),
            credentials,
            target_host: target_host.into(),
            target_port: 3389,
            connect_timeout: Duration::from_secs(10),
            auth_timeout: Duration::from_secs(10),
            connection_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_default_target_port_and_timeouts() {
        let cfg = GatewayConfig::new(
            "gw.example.com:443",
            "gw.example.com",
            NtlmCredentials::new("user", "pass", ""),
            "rdp.example.com",
        );
        assert_eq!(cfg.target_port, 3389);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(10));
        assert_eq!(cfg.auth_timeout, Duration::from_secs(10));
        assert!(cfg.connection_id.is_none());
    }

    #[test]
    fn fields_are_publicly_writable_for_tuning() {
        let mut cfg = GatewayConfig::new(
            "gw.example.com:443",
            "gw.example.com",
            NtlmCredentials::new("user", "pass", ""),
            "rdp.example.com",
        );
        cfg.target_port = 13389;
        cfg.connect_timeout = Duration::from_secs(30);
        cfg.connection_id = Some([0x42; 16]);
        assert_eq!(cfg.target_port, 13389);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(30));
        assert_eq!(cfg.connection_id, Some([0x42; 16]));
    }
}
