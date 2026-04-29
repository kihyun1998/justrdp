#![forbid(unsafe_code)]

//! Server Redirection helpers (MS-RDPBCGR §2.2.13.1, §3.1.5.4).
//!
//! When a connection broker (RD Connection Broker / Azure Virtual
//! Desktop) routes the client to a back-end RD Session Host, it sends
//! a `ServerRedirectionPdu` containing the new target address, an
//! optional load-balance cookie, optional pre-resolved credentials,
//! and (in PK-encrypted-password redirects) an opaque blob the client
//! must replay verbatim through RDSTLS to the target.
//!
//! Embedders consume the redirect like this:
//!
//! ```ignore
//! use justrdp_async::{apply_redirect, redirect_target, WebClient};
//!
//! const MAX_REDIRECTS: u32 = 5;
//! let mut config = config_builder.build();
//! let mut current_target = initial_target.to_string();
//!
//! for attempt in 0..=MAX_REDIRECTS {
//!     let transport = embedder_open_transport(&current_target).await?;
//!     let (result, transport) = WebClient::new(transport)
//!         .connect_with_upgrade(config.clone(), tls_upgrader.clone())
//!         .await?;
//!
//!     if let Some(redir) = result.server_redirection.clone() {
//!         if attempt == MAX_REDIRECTS {
//!             return Err(MyError::TooManyRedirects);
//!         }
//!         current_target = redirect_target(&redir, default_port)
//!             .unwrap_or(current_target);
//!         apply_redirect(&mut config, &redir);
//!         drop(transport); // FIN to the broker before next dial
//!         continue;
//!     }
//!     return Ok((result, transport));
//! }
//! ```
//!
//! The loop is left to the embedder because opening a fresh
//! `WebTransport` is embedder-specific (DNS resolution, gateway
//! tunnels, browser WebSocket re-dial, etc.). [`crate::Reconnectable`]
//! (Step I) wraps the loop on top of a `TransportFactory` for the
//! tokio + reconnect case.

use alloc::format;
use alloc::string::{String, ToString};

use justrdp_connector::Config;
use justrdp_pdu::rdp::redirection::{
    ServerRedirectionPdu, LB_PASSWORD_IS_PK_ENCRYPTED, LB_TARGET_NET_ADDRESS,
    LB_TARGET_NET_ADDRESSES,
};
use justrdp_pdu::x224::SecurityProtocol;

/// Hard cap on redirect chain length, matching `justrdp-blocking`.
/// Brokers typically redirect at most once or twice; five is generous
/// and short-circuits a misconfigured broker pair that bounces the
/// client between two endpoints.
pub const MAX_REDIRECTS: u32 = 5;

/// Extract a `host[:port]` string from a redirect PDU.
///
/// Priority order matches MS-RDPBCGR §2.2.13.1.1:
///   1. `target_net_address` (LB_TARGET_NET_ADDRESS) — UTF-16LE host
///      string, possibly null-terminated.
///   2. First entry of `target_net_addresses` (LB_TARGET_NET_ADDRESSES)
///      — same encoding.
///   3. `None` — the redirect carries only an LB cookie / auth state
///      change and the embedder should reconnect to the same host.
///
/// `default_port` is appended when the address string contains no
/// port. Returns `None` on UTF-16 decode failure or if neither field
/// is present.
///
/// The returned string is suitable as input to `to_socket_addrs()`
/// (or any other DNS-resolving API) on the embedder side. We don't
/// resolve here because `core::net` is unstable and `std::net` would
/// break the no_std + alloc guarantee.
pub fn redirect_target(
    redir: &ServerRedirectionPdu,
    default_port: u16,
) -> Option<String> {
    let bytes: &[u8] = if redir.redir_flags & LB_TARGET_NET_ADDRESS != 0 {
        redir.target_net_address.as_deref()?
    } else if redir.redir_flags & LB_TARGET_NET_ADDRESSES != 0 {
        redir
            .target_net_addresses
            .as_ref()
            .and_then(|tna| tna.addresses.first().map(|a| a.address.as_slice()))?
    } else {
        return None;
    };

    let raw = utf16le_to_string(bytes)?;
    let trimmed = raw.trim_end_matches('\0');
    if trimmed.is_empty() {
        return None;
    }

    // If the string already carries a port (`host:port` or
    // `[v6]:port`), pass it through unchanged. Otherwise append the
    // default port so the embedder sees a fully-qualified target.
    if has_port(trimmed) {
        Some(trimmed.to_string())
    } else {
        Some(format!("{trimmed}:{default_port}"))
    }
}

/// Mutate `config` so the next handshake honours the redirect.
///
/// Rules (matches `justrdp-blocking::client::connect_with_upgrader`):
/// - `routing_token` ← `redir.load_balance_info` (overwriting any
///   previous cookie). Brokers expect their fresh LB cookie on the
///   redirected attempt.
/// - `cookie = None` — the old `mstshash=` cookie is stale.
/// - `auto_reconnect_cookie = None` — ARC cookies are session-bound.
/// - `LB_PASSWORD_IS_PK_ENCRYPTED` + `password` present:
///   route the redirect through RDSTLS so the opaque PK-encrypted
///   blob can be passed verbatim to the target. Sets
///   `redirection_password_blob`, optionally `redirection_guid`, and
///   forces `security_protocol = SecurityProtocol::RDSTLS`.
/// - `username` / `domain` from the redirect override the config's
///   credentials (broker-supplied SSO).
pub fn apply_redirect(config: &mut Config, redir: &ServerRedirectionPdu) {
    config.routing_token = redir.load_balance_info.clone();
    config.cookie = None;
    config.auto_reconnect_cookie = None;

    if redir.redir_flags & LB_PASSWORD_IS_PK_ENCRYPTED != 0 {
        if let Some(pw) = &redir.password {
            config.redirection_password_blob = Some(pw.clone());
            config.security_protocol = SecurityProtocol::RDSTLS;
            if let Some(guid) = &redir.redirection_guid {
                config.redirection_guid = Some(guid.clone());
            }
        }
    }

    if let Some(u) = &redir.username {
        if let Some(name) = utf16le_to_string(u) {
            let trimmed = name.trim_end_matches('\0').to_string();
            if !trimmed.is_empty() {
                config.credentials.username = trimmed;
            }
        }
    }
    if let Some(d) = &redir.domain {
        if let Some(domain) = utf16le_to_string(d) {
            let trimmed = domain.trim_end_matches('\0').to_string();
            if !trimmed.is_empty() {
                config.domain = Some(trimmed);
            }
        }
    }
}

// ── Internal helpers ────────────────────────────────────────────────

/// Decode a UTF-16LE byte slice into a `String`. Stops at the first
/// embedded NUL. Returns `None` on odd byte count or invalid surrogate
/// pair. Mirrors the helper in `justrdp-blocking::client`.
fn utf16le_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut units = alloc::vec::Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let u = u16::from_le_bytes([chunk[0], chunk[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16(&units).ok()
}

/// Heuristic for `host:port` vs bare `host`. Distinguishes
/// `192.168.1.1:3389` (port present) from `192.168.1.1` (no port) and
/// also handles `[::1]:3389` (IPv6 with port) vs `[::1]` (IPv6 no port)
/// vs `::1` (bare IPv6 — counted as no-port).
fn has_port(s: &str) -> bool {
    if let Some(end) = s.rfind(']') {
        // IPv6 in brackets — port follows the closing bracket.
        return s[end..].contains(':');
    }
    // Multiple colons → bare IPv6 (no port). Single colon → host:port.
    s.matches(':').count() == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Encode `text` as UTF-16LE with a trailing NUL, mirroring how
    /// real brokers send `target_net_address`.
    fn utf16le_z(text: &str) -> alloc::vec::Vec<u8> {
        let mut v: alloc::vec::Vec<u8> = text
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        v.extend_from_slice(&[0, 0]); // NUL terminator
        v
    }

    #[test]
    fn redirect_target_uses_target_net_address_when_flag_set() {
        let redir = ServerRedirectionPdu {
            redir_flags: LB_TARGET_NET_ADDRESS,
            target_net_address: Some(utf16le_z("rdp.example.com")),
            ..Default::default()
        };
        assert_eq!(
            redirect_target(&redir, 3389),
            Some(String::from("rdp.example.com:3389"))
        );
    }

    #[test]
    fn redirect_target_preserves_explicit_port() {
        let redir = ServerRedirectionPdu {
            redir_flags: LB_TARGET_NET_ADDRESS,
            target_net_address: Some(utf16le_z("rdp.example.com:8443")),
            ..Default::default()
        };
        assert_eq!(
            redirect_target(&redir, 3389),
            Some(String::from("rdp.example.com:8443"))
        );
    }

    #[test]
    fn redirect_target_handles_ipv4_literal() {
        let redir = ServerRedirectionPdu {
            redir_flags: LB_TARGET_NET_ADDRESS,
            target_net_address: Some(utf16le_z("192.168.1.50")),
            ..Default::default()
        };
        assert_eq!(
            redirect_target(&redir, 3389),
            Some(String::from("192.168.1.50:3389"))
        );
    }

    #[test]
    fn redirect_target_returns_none_when_no_address_flag_set() {
        // LB cookie only — host stays the same; embedder should
        // reconnect to the previous target.
        let redir = ServerRedirectionPdu {
            redir_flags: 0,
            target_net_address: Some(utf16le_z("ignored.example.com")),
            ..Default::default()
        };
        assert_eq!(redirect_target(&redir, 3389), None);
    }

    #[test]
    fn redirect_target_falls_back_to_target_net_addresses() {
        use justrdp_pdu::rdp::redirection::{TargetNetAddress, TargetNetAddresses};
        let redir = ServerRedirectionPdu {
            redir_flags: LB_TARGET_NET_ADDRESSES,
            target_net_addresses: Some(TargetNetAddresses {
                addresses: vec![TargetNetAddress {
                    address: utf16le_z("backend-01.corp.local"),
                }],
            }),
            ..Default::default()
        };
        assert_eq!(
            redirect_target(&redir, 3389),
            Some(String::from("backend-01.corp.local:3389"))
        );
    }

    #[test]
    fn redirect_target_rejects_invalid_utf16_byte_count() {
        let redir = ServerRedirectionPdu {
            redir_flags: LB_TARGET_NET_ADDRESS,
            // Odd byte count — invalid UTF-16LE, should return None.
            target_net_address: Some(vec![0x66, 0x00, 0x6F]),
            ..Default::default()
        };
        assert_eq!(redirect_target(&redir, 3389), None);
    }

    #[test]
    fn apply_redirect_overwrites_routing_token_with_load_balance_info() {
        let mut config = Config::builder("alice", "p4ss").build();
        config.routing_token = Some(vec![0x01, 0x02]); // stale
        let redir = ServerRedirectionPdu {
            load_balance_info: Some(vec![0xAA, 0xBB, 0xCC]),
            ..Default::default()
        };
        apply_redirect(&mut config, &redir);
        assert_eq!(config.routing_token, Some(vec![0xAA, 0xBB, 0xCC]));
    }

    #[test]
    fn apply_redirect_clears_session_cookies() {
        use justrdp_connector::ArcCookie;
        let mut config = Config::builder("alice", "p4ss").build();
        config.cookie = Some(String::from("mstshash=alice"));
        config.auto_reconnect_cookie = Some(ArcCookie {
            logon_id: 0xDEAD_BEEF,
            arc_random_bits: [0u8; 16],
        });
        let redir = ServerRedirectionPdu::default();
        apply_redirect(&mut config, &redir);
        assert!(config.cookie.is_none());
        assert!(config.auto_reconnect_cookie.is_none());
    }

    #[test]
    fn apply_redirect_pk_encrypted_password_switches_to_rdstls() {
        let mut config = Config::builder("alice", "p4ss")
            .security_protocol(
                SecurityProtocol::SSL.union(SecurityProtocol::HYBRID),
            )
            .build();
        let redir = ServerRedirectionPdu {
            redir_flags: LB_PASSWORD_IS_PK_ENCRYPTED,
            password: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            redirection_guid: Some(vec![0x42; 16]),
            ..Default::default()
        };
        apply_redirect(&mut config, &redir);
        assert_eq!(
            config.redirection_password_blob,
            Some(vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
        assert_eq!(config.redirection_guid, Some(vec![0x42; 16]));
        assert_eq!(config.security_protocol, SecurityProtocol::RDSTLS);
    }

    #[test]
    fn apply_redirect_pk_flag_without_password_keeps_protocol() {
        // Flag set but no password — fall through to the normal auth
        // path; do not switch to RDSTLS just because the flag is set.
        let mut config = Config::builder("alice", "p4ss")
            .security_protocol(SecurityProtocol::SSL)
            .build();
        let redir = ServerRedirectionPdu {
            redir_flags: LB_PASSWORD_IS_PK_ENCRYPTED,
            password: None,
            ..Default::default()
        };
        apply_redirect(&mut config, &redir);
        assert!(config.redirection_password_blob.is_none());
        assert_eq!(config.security_protocol, SecurityProtocol::SSL);
    }

    #[test]
    fn apply_redirect_overrides_username_and_domain_from_redirect() {
        let mut config = Config::builder("alice", "p4ss").build();
        let redir = ServerRedirectionPdu {
            username: Some(utf16le_z("bob")),
            domain: Some(utf16le_z("CONTOSO")),
            ..Default::default()
        };
        apply_redirect(&mut config, &redir);
        assert_eq!(config.credentials.username, "bob");
        assert_eq!(config.domain.as_deref(), Some("CONTOSO"));
    }

    #[test]
    fn apply_redirect_empty_username_does_not_clobber() {
        let mut config = Config::builder("alice", "p4ss").build();
        let redir = ServerRedirectionPdu {
            username: Some(utf16le_z("")), // explicit empty
            ..Default::default()
        };
        apply_redirect(&mut config, &redir);
        // Empty username from broker is meaningless — keep the original.
        assert_eq!(config.credentials.username, "alice");
    }

    #[test]
    fn has_port_distinguishes_host_port_from_bare_host() {
        assert!(has_port("rdp.example.com:3389"));
        assert!(has_port("192.168.1.1:3389"));
        assert!(!has_port("rdp.example.com"));
        assert!(!has_port("192.168.1.1"));
    }

    #[test]
    fn has_port_handles_ipv6_literals() {
        assert!(has_port("[::1]:3389"));
        assert!(!has_port("[::1]"));
        assert!(!has_port("::1")); // bare IPv6 — multiple colons, no brackets
        assert!(!has_port("fe80::1")); // bare IPv6
    }
}
