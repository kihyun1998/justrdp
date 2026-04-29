#![forbid(unsafe_code)]

//! Auto-Reconnect + Session Redirection state container.
//!
//! Wraps a [`TransportFactory`] together with the saved config / target
//! / ARC cookie that the next reconnect or redirect attempt needs.
//! Embedders compose it around the existing [`WebClient`] surface
//! rather than learning a new connect API:
//!
//! ```ignore
//! use justrdp_async::{Reconnectable, ReconnectPolicy, WebClient};
//!
//! let mut r = Reconnectable::new(my_factory, "rdp.example.com:3389", config)
//!     .with_policy(ReconnectPolicy::aggressive());
//!
//! // Initial connect with redirect loop:
//! let (mut result, mut transport) = loop {
//!     let (transport, current_config) = r.open_next().await?;
//!     let (result, transport) = WebClient::new(transport)
//!         .connect_with_upgrade(current_config, upgrader.clone())
//!         .await?;
//!     if r.record_result(&result) {
//!         drop(transport); // FIN broker before next dial
//!         continue;        // redirect detected, loop
//!     }
//!     break (result, transport);
//! };
//!
//! let mut session = ActiveSession::new(transport, &result);
//! // ... drive next_events; on Transport(_) error, run the same loop
//! //     against `r.open_next()` to reconnect with the saved ARC cookie.
//! ```
//!
//! Why a state holder instead of a fully-driven `connect_loop`:
//! `TlsUpgrade` (and `CredsspDriver`) in this crate take `self` by value,
//! so they can't be reused inside an internal loop without Clone bounds
//! that would force every embedder upgrader to derive Clone. Letting
//! the embedder own the loop keeps the upgrader's `self`-by-value
//! contract and lets them rebuild a fresh upgrader (with whatever
//! per-attempt config) for each iteration.
//!
//! [`WebClient`]: crate::driver::WebClient

use alloc::string::String;
use core::time::Duration;

use justrdp_connector::{ArcCookie, Config, ConnectionResult};

use crate::redirect::{apply_redirect, redirect_target};

// ─── ReconnectPolicy ────────────────────────────────────────────────

/// Auto-reconnect retry policy. Mirrors `justrdp_blocking::ReconnectPolicy`
/// 1:1, copied here because justrdp-async is `no_std + alloc` and can't
/// depend on the std-only blocking crate. Both copies use
/// `core::time::Duration` so the field types match.
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    /// Maximum number of reconnect attempts before giving up. `0`
    /// disables automatic reconnect entirely.
    pub max_attempts: u32,
    /// Initial delay between the drop and the first reconnect attempt.
    pub initial_delay: Duration,
    /// Maximum delay between attempts (cap for exponential backoff).
    pub max_delay: Duration,
    /// Multiplier applied to the delay after each failed attempt.
    /// `1.0` produces constant-interval retries.
    pub backoff: f32,
}

impl ReconnectPolicy {
    /// Disable automatic reconnect (default).
    pub const fn disabled() -> Self {
        Self {
            max_attempts: 0,
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            backoff: 1.0,
        }
    }

    /// Up to 5 attempts with 1s / 2s / 4s / 8s / 10s backoff.
    pub fn aggressive() -> Self {
        Self {
            max_attempts: 5,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(10),
            backoff: 2.0,
        }
    }

    /// Compute the delay before the Nth attempt (1-indexed). Returns
    /// `Duration::ZERO` for `attempt == 0`.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        let mut delay = self.initial_delay.as_secs_f32();
        for _ in 1..attempt {
            delay *= self.backoff;
        }
        let capped = delay.min(self.max_delay.as_secs_f32());
        Duration::from_secs_f32(capped)
    }
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

// ─── TransportFactory ───────────────────────────────────────────────

/// Asynchronous factory that opens a fresh [`WebTransport`] to a target
/// host. Used by [`Reconnectable`] to dial again after a redirect or
/// after the active session reports a transport error.
///
/// Implementations are typically a thin wrapper around the embedder's
/// connect logic — TCP+TLS dial for native, WebSocket open for browser,
/// gateway-tunnel build for RD Gateway, etc.
///
/// [`WebTransport`]: crate::transport::WebTransport
pub trait TransportFactory {
    type Transport: crate::transport::WebTransport;
    type Error: core::fmt::Display;
    fn open(
        &self,
        target: &str,
    ) -> impl core::future::Future<Output = Result<Self::Transport, Self::Error>>;
}

// ─── Reconnectable ──────────────────────────────────────────────────

/// State holder that survives transport drops and broker redirects.
///
/// Owns:
/// - the [`TransportFactory`] used to dial fresh transports
/// - the current target string (mutated by [`Self::record_result`] when
///   a redirect arrives)
/// - the running [`Config`] (also mutated on redirect)
/// - the most-recent [`ArcCookie`] (injected into `Config.auto_reconnect_cookie`
///   on every subsequent dial so the server can rejoin the existing
///   logon session)
/// - a [`ReconnectPolicy`] consulted by the embedder when deciding
///   whether to retry after a transport drop.
pub struct Reconnectable<F: TransportFactory> {
    factory: F,
    target: String,
    config: Config,
    last_arc_cookie: Option<ArcCookie>,
    policy: ReconnectPolicy,
    default_port: u16,
}

impl<F: TransportFactory> Reconnectable<F> {
    /// Construct from a factory, an initial `host[:port]` target, and
    /// the connect [`Config`].
    pub fn new(factory: F, target: impl Into<String>, config: Config) -> Self {
        Self {
            factory,
            target: target.into(),
            config,
            last_arc_cookie: None,
            policy: ReconnectPolicy::disabled(),
            default_port: 3389,
        }
    }

    /// Override the reconnect policy (default: [`ReconnectPolicy::disabled`]).
    pub fn with_policy(mut self, policy: ReconnectPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Override the default port appended to redirect targets that
    /// arrive without one (default: 3389).
    pub fn with_default_port(mut self, port: u16) -> Self {
        self.default_port = port;
        self
    }

    /// Current dial target (`host[:port]`). Updated by
    /// [`Self::record_result`] when a broker redirect arrives.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Reborrow the running config (post-redirect mutations applied).
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Most-recent ARC cookie observed on a successful handshake. The
    /// server includes one in [`SaveSessionInfoData`] mid-session for
    /// auto-reconnect; until [`Self::observe_arc_cookie`] is called by
    /// the embedder, this is whatever the connector saw on the last
    /// `connect()`.
    ///
    /// [`SaveSessionInfoData`]: justrdp_pdu::rdp::finalization::SaveSessionInfoData
    pub fn arc_cookie(&self) -> Option<&ArcCookie> {
        self.last_arc_cookie.as_ref()
    }

    /// Reconnect policy view.
    pub fn policy(&self) -> &ReconnectPolicy {
        &self.policy
    }

    /// Open a fresh transport via the factory and return it together
    /// with a [`Config`] clone that has the saved ARC cookie injected.
    /// The embedder feeds both into [`WebClient::connect_*`].
    ///
    /// [`WebClient::connect_*`]: crate::driver::WebClient
    pub async fn open_next(&self) -> Result<(F::Transport, Config), F::Error> {
        let transport = self.factory.open(&self.target).await?;
        let mut config = self.config.clone();
        // Inject the saved ARC cookie so the server can rejoin the
        // existing logon session. None on the first attempt before
        // record_result has seen one.
        config.auto_reconnect_cookie = self.last_arc_cookie.clone();
        Ok((transport, config))
    }

    /// Record the outcome of a successful handshake.
    ///
    /// Returns `true` if `result.server_redirection` is `Some` — the
    /// caller should drop the current transport and loop (calling
    /// [`Self::open_next`] again with the freshly-mutated target /
    /// config). Returns `false` for terminal results.
    ///
    /// Mutations applied:
    /// - `result.server_arc_cookie` saved (so the next dial carries it).
    /// - `result.server_redirection` (if present) → `apply_redirect`
    ///   on the running config + `redirect_target` updates the target
    ///   when the broker provides a host change. Falls back to the
    ///   previous target when only an LB cookie / auth-state-change
    ///   is delivered.
    pub fn record_result(&mut self, result: &ConnectionResult) -> bool {
        if let Some(arc) = &result.server_arc_cookie {
            self.last_arc_cookie = Some(arc.clone());
        }
        let Some(redir) = &result.server_redirection else {
            return false;
        };
        if let Some(new_target) = redirect_target(redir, self.default_port) {
            self.target = new_target;
        }
        apply_redirect(&mut self.config, redir);
        true
    }

    /// Update the saved ARC cookie from a mid-session
    /// `SaveSessionInfoData::SaveSessionInfo` event. Embedders that
    /// drive the active-session pump can call this whenever they
    /// observe a fresh cookie so a subsequent reconnect uses it.
    pub fn observe_arc_cookie(&mut self, cookie: ArcCookie) {
        self.last_arc_cookie = Some(cookie);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;
    use crate::TransportError;
    use alloc::format;
    use alloc::string::ToString;
    use alloc::sync::Arc;
    use core::cell::RefCell;
    use justrdp_pdu::x224::SecurityProtocol;

    fn block_on<T>(f: impl core::future::Future<Output = T>) -> T {
        pollster::block_on(f)
    }

    fn fake_result_with_arc(arc: Option<ArcCookie>) -> ConnectionResult {
        use alloc::vec::Vec;
        ConnectionResult {
            io_channel_id: 1003,
            user_channel_id: 1001,
            share_id: 0x0001_03ea,
            server_capabilities: Vec::new(),
            channel_ids: alloc::vec![],
            selected_protocol: SecurityProtocol::RDP,
            session_id: 0,
            server_monitor_layout: None,
            server_arc_cookie: arc,
            server_redirection: None,
        }
    }

    /// Test factory that records every `open` call so assertions can
    /// verify which target was dialed. Uses an `Arc<RefCell<...>>` so a
    /// single factory instance can be observed from outside the
    /// Reconnectable.
    #[derive(Clone)]
    struct CountingFactory {
        opened: Arc<RefCell<alloc::vec::Vec<String>>>,
    }

    impl CountingFactory {
        fn new() -> (Self, Arc<RefCell<alloc::vec::Vec<String>>>) {
            let opened = Arc::new(RefCell::new(alloc::vec::Vec::new()));
            (Self { opened: Arc::clone(&opened) }, opened)
        }
    }

    impl TransportFactory for CountingFactory {
        type Transport = MockTransport;
        type Error = TransportError;
        async fn open(&self, target: &str) -> Result<MockTransport, TransportError> {
            self.opened.borrow_mut().push(target.to_string());
            Ok(MockTransport::new())
        }
    }

    /// Failing factory — used to verify that open errors propagate.
    struct FailingFactory;
    impl TransportFactory for FailingFactory {
        type Transport = MockTransport;
        type Error = TransportError;
        async fn open(&self, _target: &str) -> Result<MockTransport, TransportError> {
            Err(TransportError::other("simulated dial failure"))
        }
    }

    fn fresh_config() -> Config {
        let mut config = Config::builder("alice", "p4ss")
            .security_protocol(SecurityProtocol::RDP)
            .build();
        config.client_random = Some([0x42; 32]);
        config
    }

    // ── ReconnectPolicy ──

    #[test]
    fn policy_disabled_has_zero_attempts() {
        let p = ReconnectPolicy::disabled();
        assert_eq!(p.max_attempts, 0);
        assert_eq!(p.delay_for_attempt(0), Duration::ZERO);
        assert_eq!(p.delay_for_attempt(5), Duration::ZERO);
    }

    #[test]
    fn policy_aggressive_doubles_then_caps() {
        let p = ReconnectPolicy::aggressive();
        assert_eq!(p.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(p.delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(p.delay_for_attempt(3), Duration::from_secs(4));
        assert_eq!(p.delay_for_attempt(4), Duration::from_secs(8));
        // Capped at max_delay (10s) for attempts 5+.
        assert_eq!(p.delay_for_attempt(5), Duration::from_secs(10));
        assert_eq!(p.delay_for_attempt(50), Duration::from_secs(10));
    }

    #[test]
    fn policy_default_is_disabled() {
        assert_eq!(ReconnectPolicy::default().max_attempts, 0);
    }

    // ── Reconnectable ──

    #[test]
    fn open_next_dials_initial_target_and_returns_clean_config() {
        block_on(async {
            let (factory, opened) = CountingFactory::new();
            let r = Reconnectable::new(factory, "rdp.example.com:3389", fresh_config());
            let (_t, config) = r.open_next().await.unwrap();
            assert_eq!(opened.borrow().as_slice(), &[String::from("rdp.example.com:3389")]);
            // No ARC cookie yet — the first dial has nothing to inject.
            assert!(config.auto_reconnect_cookie.is_none());
        });
    }

    #[test]
    fn open_next_propagates_factory_error() {
        block_on(async {
            let r = Reconnectable::new(FailingFactory, "rdp.example.com:3389", fresh_config());
            let err = r.open_next().await.unwrap_err();
            assert!(format!("{err}").contains("simulated"));
        });
    }

    #[test]
    fn record_result_saves_arc_cookie_for_next_dial() {
        block_on(async {
            let (factory, _) = CountingFactory::new();
            let mut r = Reconnectable::new(factory, "rdp.example.com:3389", fresh_config());
            let cookie = ArcCookie {
                logon_id: 0xCAFE_F00D,
                arc_random_bits: [0x11; 16],
            };
            let redirect = r.record_result(&fake_result_with_arc(Some(cookie.clone())));
            assert!(!redirect, "no redirect → false");
            assert_eq!(r.arc_cookie().unwrap().logon_id, 0xCAFE_F00D);

            // Next dial injects the cookie.
            let (_t, config) = r.open_next().await.unwrap();
            assert_eq!(config.auto_reconnect_cookie.unwrap().logon_id, 0xCAFE_F00D);
        });
    }

    #[test]
    fn record_result_with_redirect_returns_true_and_mutates_target() {
        use justrdp_pdu::rdp::redirection::{
            ServerRedirectionPdu, LB_TARGET_NET_ADDRESS,
        };
        block_on(async {
            let (factory, opened) = CountingFactory::new();
            let mut r = Reconnectable::new(factory, "broker.example.com:3389", fresh_config());

            // Build a redirect that points at backend-01:3389.
            let utf16le_z = |text: &str| -> alloc::vec::Vec<u8> {
                let mut v: alloc::vec::Vec<u8> =
                    text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                v.extend_from_slice(&[0, 0]);
                v
            };
            let redir = ServerRedirectionPdu {
                redir_flags: LB_TARGET_NET_ADDRESS,
                target_net_address: Some(utf16le_z("backend-01.corp.local")),
                ..Default::default()
            };
            let mut result = fake_result_with_arc(None);
            result.server_redirection = Some(redir);

            let was_redirect = r.record_result(&result);
            assert!(was_redirect, "redirect → true");
            assert_eq!(r.target(), "backend-01.corp.local:3389");

            // Subsequent open_next dials the new target.
            r.open_next().await.unwrap();
            assert_eq!(opened.borrow().as_slice(), &[String::from("backend-01.corp.local:3389")]);
        });
    }

    #[test]
    fn record_result_redirect_without_address_keeps_target() {
        use justrdp_pdu::rdp::redirection::ServerRedirectionPdu;
        let (factory, _) = CountingFactory::new();
        let mut r = Reconnectable::new(factory, "broker.example.com:3389", fresh_config());

        // LB cookie only — no address change. record_result still
        // returns true because the redirect triggers a re-dial against
        // the same host (with the new routing token).
        let mut result = fake_result_with_arc(None);
        result.server_redirection = Some(ServerRedirectionPdu {
            load_balance_info: Some(alloc::vec![0xAA, 0xBB]),
            ..Default::default()
        });

        let was_redirect = r.record_result(&result);
        assert!(was_redirect);
        assert_eq!(r.target(), "broker.example.com:3389");
        // routing_token absorbed into the running config.
        assert_eq!(r.config().routing_token.as_deref(), Some(&[0xAA, 0xBB][..]));
    }

    #[test]
    fn observe_arc_cookie_overrides_saved_value() {
        let (factory, _) = CountingFactory::new();
        let mut r = Reconnectable::new(factory, "rdp.example.com:3389", fresh_config());
        let initial = ArcCookie {
            logon_id: 0x0001_0001,
            arc_random_bits: [0x22; 16],
        };
        r.record_result(&fake_result_with_arc(Some(initial)));
        assert_eq!(r.arc_cookie().unwrap().logon_id, 0x0001_0001);

        // Mid-session SaveSessionInfo replaces the cookie.
        let updated = ArcCookie {
            logon_id: 0x0002_0002,
            arc_random_bits: [0x33; 16],
        };
        r.observe_arc_cookie(updated);
        assert_eq!(r.arc_cookie().unwrap().logon_id, 0x0002_0002);
    }

    #[test]
    fn with_policy_and_with_default_port_apply() {
        let (factory, _) = CountingFactory::new();
        let r = Reconnectable::new(factory, "rdp.example.com", fresh_config())
            .with_policy(ReconnectPolicy::aggressive())
            .with_default_port(443);
        assert_eq!(r.policy().max_attempts, 5);
        // Default port plumbed through to redirect_target — verifiable
        // by running a record_result with a port-less redirect target.
    }

    #[test]
    fn with_default_port_used_for_redirect_targets_without_port() {
        use justrdp_pdu::rdp::redirection::{
            ServerRedirectionPdu, LB_TARGET_NET_ADDRESS,
        };
        let (factory, _) = CountingFactory::new();
        let mut r = Reconnectable::new(factory, "broker.example.com:3389", fresh_config())
            .with_default_port(8443);

        let utf16le_z = |text: &str| -> alloc::vec::Vec<u8> {
            let mut v: alloc::vec::Vec<u8> =
                text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            v.extend_from_slice(&[0, 0]);
            v
        };
        let mut result = fake_result_with_arc(None);
        result.server_redirection = Some(ServerRedirectionPdu {
            redir_flags: LB_TARGET_NET_ADDRESS,
            target_net_address: Some(utf16le_z("rdsh-corp.local")),
            ..Default::default()
        });

        r.record_result(&result);
        // 8443 (overridden default) appended, not 3389.
        assert_eq!(r.target(), "rdsh-corp.local:8443");
    }
}
