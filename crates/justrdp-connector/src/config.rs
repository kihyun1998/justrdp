#![forbid(unsafe_code)]

//! Connection configuration.

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_pdu::gcc::client::ChannelDef;
use justrdp_pdu::rdp::client_info::PerformanceFlags;
use justrdp_pdu::x224::SecurityProtocol;

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
                security_protocol: SecurityProtocol::SSL.union(SecurityProtocol::HYBRID),
                cookie: None,
                client_name: String::new(),
                channels: Vec::new(),
                performance_flags: PerformanceFlags::from_bits(0),
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

    /// Build the configuration.
    pub fn build(self) -> Config {
        self.config
    }
}
