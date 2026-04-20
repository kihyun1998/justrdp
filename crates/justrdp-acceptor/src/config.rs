#![forbid(unsafe_code)]

//! Acceptor configuration.

use justrdp_pdu::x224::SecurityProtocol;

/// Configuration for `ServerAcceptor`.
///
/// Phase 1 (X.224 Negotiate) needs only the security-protocol related
/// fields; later phases (MCS, capabilities, licensing) will extend this
/// struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptorConfig {
    /// Bitmask of security protocols this server is willing to accept.
    /// Typical default: `SSL | HYBRID | HYBRID_EX`.
    pub supported_protocols: SecurityProtocol,
    /// If `true`, the server refuses Standard RDP Security and emits
    /// `SSL_REQUIRED_BY_SERVER` when a client requests only `PROTOCOL_RDP`.
    pub require_enhanced_security: bool,
    /// Set when no usable TLS certificate is available at the time of
    /// Connection Request handling. When `true` and the negotiation would
    /// pick TLS/CredSSP/RDSTLS, the acceptor instead emits
    /// `SSL_CERT_NOT_ON_SERVER`.
    pub tls_certificate_available: bool,
    /// Whether to advertise `RESTRICTED_ADMIN_MODE_SUPPORTED (0x08)` in
    /// `RDP_NEG_RSP.flags`. The flag is only set when the client also
    /// requested `RESTRICTED_ADMIN_MODE_REQUIRED`.
    pub restricted_admin_supported: bool,
    /// Whether to advertise `REDIRECTED_AUTHENTICATION_MODE_SUPPORTED
    /// (0x10)` in `RDP_NEG_RSP.flags`. The flag is only set when the
    /// client also requested `REDIRECTED_AUTHENTICATION_MODE_REQUIRED`.
    pub redirected_auth_supported: bool,
    /// Whether to set `EXTENDED_CLIENT_DATA_SUPPORTED (0x01)` in
    /// `RDP_NEG_RSP.flags` (MS-RDPBCGR 2.2.1.2.1). Modern servers always
    /// set this; included as a knob for testing legacy interop.
    pub extended_client_data_supported: bool,
    /// Whether to set `DYNVC_GFX_PROTOCOL_SUPPORTED (0x02)` in
    /// `RDP_NEG_RSP.flags`. Indicates server-side support for the
    /// MS-RDPEGFX Graphics Pipeline.
    pub gfx_supported: bool,

    // ── Phase 4: MCS Connect Response ──────────────────────────────────

    /// Server RDP version reported in `SC_CORE.version` (MS-RDPBCGR
    /// §2.2.1.4.2). Default: RDP 10.7 = `0x000A_0007`.
    pub server_rdp_version: u32,
    /// Optional `earlyCapabilityFlags` for `SC_CORE` (MS-RDPBCGR
    /// §2.2.1.4.2). `None` -> field omitted on the wire.
    pub server_early_capability_flags: Option<u32>,
    /// Whether to allocate an MCS message channel (and emit
    /// `SC_MCS_MSGCHANNEL`) when the client included `CS_MCS_MSGCHANNEL`
    /// in its CR. The channel itself is used by Auto-Detect /
    /// Multitransport Bootstrapping.
    pub support_message_channel: bool,
    /// Whether to advertise `SC_MULTITRANSPORT` in the Connect Response.
    /// `None` -> block omitted; `Some(flags)` -> block sent with the
    /// given `flags` (e.g. `SOFTSYNC | TUNNEL_UDP_FECR`).
    pub multitransport_flags: Option<u32>,
}

impl Default for AcceptorConfig {
    fn default() -> Self {
        Self {
            supported_protocols: SecurityProtocol::SSL
                .union(SecurityProtocol::HYBRID)
                .union(SecurityProtocol::HYBRID_EX),
            require_enhanced_security: true,
            tls_certificate_available: true,
            restricted_admin_supported: false,
            redirected_auth_supported: false,
            extended_client_data_supported: true,
            gfx_supported: false,
            // RDP 10.7 (0x000A_0007) -- matches what Windows Server 2019+
            // advertises and is high enough to enable Surface Commands /
            // EGFX without forcing the extra optional `SC_CORE` fields.
            server_rdp_version: 0x000A_0007,
            server_early_capability_flags: None,
            support_message_channel: false,
            multitransport_flags: None,
        }
    }
}

impl AcceptorConfig {
    /// Start a new builder pre-populated with default values.
    pub fn builder() -> AcceptorConfigBuilder {
        AcceptorConfigBuilder::new()
    }
}

/// Builder for [`AcceptorConfig`].
#[derive(Debug, Clone)]
pub struct AcceptorConfigBuilder {
    inner: AcceptorConfig,
}

impl AcceptorConfigBuilder {
    pub fn new() -> Self {
        Self {
            inner: AcceptorConfig::default(),
        }
    }

    pub fn supported_protocols(mut self, protocols: SecurityProtocol) -> Self {
        self.inner.supported_protocols = protocols;
        self
    }

    pub fn require_enhanced_security(mut self, require: bool) -> Self {
        self.inner.require_enhanced_security = require;
        self
    }

    pub fn tls_certificate_available(mut self, available: bool) -> Self {
        self.inner.tls_certificate_available = available;
        self
    }

    pub fn restricted_admin_supported(mut self, supported: bool) -> Self {
        self.inner.restricted_admin_supported = supported;
        self
    }

    pub fn redirected_auth_supported(mut self, supported: bool) -> Self {
        self.inner.redirected_auth_supported = supported;
        self
    }

    pub fn extended_client_data_supported(mut self, supported: bool) -> Self {
        self.inner.extended_client_data_supported = supported;
        self
    }

    pub fn gfx_supported(mut self, supported: bool) -> Self {
        self.inner.gfx_supported = supported;
        self
    }

    pub fn server_rdp_version(mut self, version: u32) -> Self {
        self.inner.server_rdp_version = version;
        self
    }

    pub fn server_early_capability_flags(mut self, flags: Option<u32>) -> Self {
        self.inner.server_early_capability_flags = flags;
        self
    }

    pub fn support_message_channel(mut self, supported: bool) -> Self {
        self.inner.support_message_channel = supported;
        self
    }

    pub fn multitransport_flags(mut self, flags: Option<u32>) -> Self {
        self.inner.multitransport_flags = flags;
        self
    }

    /// Validate and return the built config.
    ///
    /// Returns an error when the config would create a MITM-aided
    /// downgrade window: `supported_protocols` advertises enhanced
    /// security bits (SSL/HYBRID/HYBRID_EX/RDSTLS/AAD) but
    /// `require_enhanced_security` is false. In that combination, a
    /// man-in-the-middle can strip all `requestedProtocols` bits from
    /// the client's CR to force `PROTOCOL_RDP` selection even though
    /// the server actually supports TLS.
    ///
    /// Use [`build_allow_downgrade`](Self::build_allow_downgrade) if
    /// you explicitly want to accept this risk (legacy interop).
    pub fn build(self) -> Result<AcceptorConfig, crate::error::AcceptorConfigError> {
        use justrdp_pdu::x224::SecurityProtocol;
        let has_enhanced =
            self.inner.supported_protocols.bits() & !SecurityProtocol::RDP.bits() != 0;
        if has_enhanced && !self.inner.require_enhanced_security {
            return Err(crate::error::AcceptorConfigError::DowngradeRisk);
        }
        Ok(self.inner)
    }

    /// Like [`build`](Self::build) but skips the downgrade-safety
    /// invariant. Only use this when you need to accept legacy
    /// Standard-RDP-Security clients while also serving TLS clients --
    /// accept that MITM can force-downgrade to RC4 in that mode.
    pub fn build_allow_downgrade(self) -> AcceptorConfig {
        self.inner
    }
}

impl Default for AcceptorConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::x224::SecurityProtocol;

    #[test]
    fn build_rejects_downgrade_combo() {
        // Enhanced bits advertised + require_enhanced_security=false
        // is the exact combination a MITM can exploit.
        let err = AcceptorConfig::builder()
            .supported_protocols(
                SecurityProtocol::SSL.union(SecurityProtocol::HYBRID),
            )
            .require_enhanced_security(false)
            .build()
            .unwrap_err();
        assert_eq!(err, crate::error::AcceptorConfigError::DowngradeRisk);
        // Display formatter should mention "downgrade" for log grepping.
        assert!(alloc::format!("{err}").contains("downgrade"));
    }

    #[test]
    fn build_accepts_rdp_only_with_enhanced_off() {
        // Pure Standard-RDP-Security server is safe: there are no
        // enhanced bits to downgrade from.
        let cfg = AcceptorConfig::builder()
            .supported_protocols(SecurityProtocol::RDP)
            .require_enhanced_security(false)
            .build()
            .unwrap();
        assert_eq!(cfg.supported_protocols, SecurityProtocol::RDP);
    }

    #[test]
    fn build_accepts_enhanced_with_require_on() {
        let cfg = AcceptorConfig::builder()
            .supported_protocols(SecurityProtocol::HYBRID)
            .require_enhanced_security(true)
            .build()
            .unwrap();
        assert_eq!(cfg.supported_protocols, SecurityProtocol::HYBRID);
    }

    #[test]
    fn build_allow_downgrade_bypasses_invariant() {
        // Explicit opt-in for legacy interop.
        let cfg = AcceptorConfig::builder()
            .supported_protocols(
                SecurityProtocol::SSL.union(SecurityProtocol::HYBRID),
            )
            .require_enhanced_security(false)
            .build_allow_downgrade();
        assert!(!cfg.require_enhanced_security);
    }
}
