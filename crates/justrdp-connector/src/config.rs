#![forbid(unsafe_code)]

//! Connection configuration.

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_pdu::gcc::client::ChannelDef;
use justrdp_pdu::rdp::client_info::PerformanceFlags;
use justrdp_pdu::x224::SecurityProtocol;

/// Authentication mode for the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Standard password-based authentication (default).
    Password,
    /// Remote Credential Guard: Kerberos-based SSO without password delegation.
    /// The client's Kerberos service ticket is forwarded instead of credentials.
    RemoteCredentialGuard,
    /// Restricted Admin: no credentials are sent to the server.
    /// The session uses the server's machine account for network resources.
    RestrictedAdmin,
}

/// RDP connection configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Domain name (empty string if none).
    pub domain: String,
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
    /// Desktop width in pixels.
    pub desktop_width: u16,
    /// Desktop height in pixels.
    pub desktop_height: u16,
    /// Keyboard layout (LCID). Default: 0x0409 (US English).
    pub keyboard_layout: u32,
    /// Keyboard type. Default: 4 (IBM enhanced 101/102).
    pub keyboard_type: u32,
    /// Keyboard subtype. Default: 0.
    pub keyboard_subtype: u32,
    /// Color depth in bits per pixel. Default: 16.
    pub color_depth: u16,
    /// Client build number sent in version info. Default: 22621 (Windows 11 22H2).
    pub client_build: u32,
    /// Auto-reconnect cookie from a previous session (optional).
    pub auto_reconnect_cookie: Option<Vec<u8>>,
    /// Requested security protocol(s).
    pub security_protocol: SecurityProtocol,
    /// RDP cookie for load balancing (optional).
    pub cookie: Option<String>,
    /// Client name sent to server.
    pub client_name: String,
    /// Static virtual channels to request.
    pub channels: Vec<ChannelDef>,
    /// Performance flags.
    pub performance_flags: PerformanceFlags,
    /// Authentication mode.
    pub auth_mode: AuthMode,
    /// Kerberos AP-REQ token for Remote Credential Guard.
    /// Must be provided when auth_mode is RemoteCredentialGuard.
    pub kerberos_token: Option<Vec<u8>>,
    /// Device Kerberos AP-REQ token for Compound Identity (optional).
    pub device_kerberos_token: Option<Vec<u8>>,
    /// Client random for Standard RDP Security key exchange (32 bytes).
    /// Must be cryptographically random. If None, Standard RDP Security is not available.
    pub client_random: Option<[u8; 32]>,
}

impl Config {
    /// Create a builder with the given credentials.
    pub fn builder(username: &str, password: &str) -> ConfigBuilder {
        ConfigBuilder {
            config: Config {
                domain: String::new(),
                username: String::from(username),
                password: String::from(password),
                desktop_width: 1024,
                desktop_height: 768,
                keyboard_layout: 0x0409,
                keyboard_type: 4,
                keyboard_subtype: 0,
                color_depth: 16,
                client_build: 22621,
                auto_reconnect_cookie: None,
                security_protocol: SecurityProtocol::SSL.union(SecurityProtocol::HYBRID),
                cookie: None,
                client_name: String::new(),
                channels: Vec::new(),
                performance_flags: PerformanceFlags::from_bits(0),
                auth_mode: AuthMode::Password,
                kerberos_token: None,
                device_kerberos_token: None,
                client_random: None,
            },
        }
    }
}

/// Builder for [`Config`].
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Set the domain.
    pub fn domain(mut self, domain: &str) -> Self {
        self.config.domain = String::from(domain);
        self
    }

    /// Set the desktop resolution.
    pub fn desktop_size(mut self, width: u16, height: u16) -> Self {
        self.config.desktop_width = width;
        self.config.desktop_height = height;
        self
    }

    /// Set the keyboard layout (LCID).
    pub fn keyboard_layout(mut self, layout: u32) -> Self {
        self.config.keyboard_layout = layout;
        self
    }

    /// Set the keyboard type.
    pub fn keyboard_type(mut self, kb_type: u32) -> Self {
        self.config.keyboard_type = kb_type;
        self
    }

    /// Set the requested security protocol(s).
    pub fn security_protocol(mut self, proto: SecurityProtocol) -> Self {
        self.config.security_protocol = proto;
        self
    }

    /// Set the RDP cookie for load balancing.
    pub fn cookie(mut self, cookie: &str) -> Self {
        self.config.cookie = Some(String::from(cookie));
        self
    }

    /// Set the client name.
    pub fn client_name(mut self, name: &str) -> Self {
        self.config.client_name = String::from(name);
        self
    }

    /// Add a static virtual channel.
    pub fn channel(mut self, name: &str, options: u32) -> Self {
        self.config.channels.push(ChannelDef::new(name, options));
        self
    }

    /// Set performance flags.
    pub fn performance_flags(mut self, flags: PerformanceFlags) -> Self {
        self.config.performance_flags = flags;
        self
    }

    /// Set authentication mode.
    pub fn auth_mode(mut self, mode: AuthMode) -> Self {
        self.config.auth_mode = mode;
        self
    }

    /// Enable Remote Credential Guard with a Kerberos AP-REQ token.
    ///
    /// Sets auth mode to RemoteCredentialGuard and protocol to RDSTLS.
    /// The `kerberos_token` is the AP-REQ obtained from the KDC for the target server.
    pub fn remote_credential_guard(mut self, kerberos_token: Vec<u8>) -> Self {
        self.config.auth_mode = AuthMode::RemoteCredentialGuard;
        self.config.security_protocol = SecurityProtocol::RDSTLS;
        self.config.kerberos_token = Some(kerberos_token);
        self
    }

    /// Set a device Kerberos token for Compound Identity (optional).
    ///
    /// Used with Remote Credential Guard to include device claims
    /// in the authentication for conditional access evaluation.
    pub fn device_kerberos_token(mut self, token: Vec<u8>) -> Self {
        self.config.device_kerberos_token = Some(token);
        self
    }

    /// Enable Restricted Admin mode.
    ///
    /// Forces HYBRID (CredSSP/NLA) protocol since Restricted Admin requires NLA.
    pub fn restricted_admin(mut self) -> Self {
        self.config.auth_mode = AuthMode::RestrictedAdmin;
        // Restricted Admin requires CredSSP (HYBRID)
        if !self.config.security_protocol.contains(SecurityProtocol::HYBRID)
            && !self.config.security_protocol.contains(SecurityProtocol::HYBRID_EX)
        {
            self.config.security_protocol = SecurityProtocol::HYBRID;
        }
        self
    }

    /// Set the client random for Standard RDP Security (32 bytes, must be cryptographic random).
    pub fn client_random(mut self, random: [u8; 32]) -> Self {
        self.config.client_random = Some(random);
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Config {
        self.config
    }
}
