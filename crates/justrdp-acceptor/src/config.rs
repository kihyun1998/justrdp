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

    pub fn build(self) -> AcceptorConfig {
        self.inner
    }
}

impl Default for AcceptorConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
