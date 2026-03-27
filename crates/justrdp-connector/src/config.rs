#![forbid(unsafe_code)]

//! Connection configuration.

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_pdu::gcc::client::ChannelDef;
use justrdp_pdu::rdp::client_info::PerformanceFlags;
use justrdp_pdu::x224::SecurityProtocol;

/// Authentication credentials.
#[derive(Debug, Clone)]
pub struct Credentials {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
}

/// Desktop size in pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopSize {
    /// Width in pixels.
    pub width: u16,
    /// Height in pixels.
    pub height: u16,
}

impl DesktopSize {
    pub fn new(width: u16, height: u16) -> Self {
        Self { width, height }
    }
}

/// Keyboard type (MS-RDPBCGR 2.2.1.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyboardType {
    /// IBM PC/XT or compatible (83-key).
    IbmPcXt = 1,
    /// Olivetti "ICO" (102-key).
    OlivettiIco = 2,
    /// IBM PC/AT (84-key) or similar.
    IbmPcAt = 3,
    /// IBM enhanced (101- or 102-key).
    IbmEnhanced = 4,
    /// Nokia 1050 or similar.
    Nokia1050 = 5,
    /// Nokia 9140 or similar.
    Nokia9140 = 6,
    /// Japanese keyboard.
    Japanese = 7,
}

impl KeyboardType {
    /// Convert from a raw u32 value, defaulting to IbmEnhanced.
    pub fn from_u32(val: u32) -> Self {
        match val {
            1 => Self::IbmPcXt,
            2 => Self::OlivettiIco,
            3 => Self::IbmPcAt,
            4 => Self::IbmEnhanced,
            5 => Self::Nokia1050,
            6 => Self::Nokia9140,
            7 => Self::Japanese,
            _ => Self::IbmEnhanced,
        }
    }

    /// Get the raw u32 value.
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Color depth for the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ColorDepth {
    Bpp8 = 8,
    Bpp15 = 15,
    Bpp16 = 16,
    Bpp24 = 24,
    Bpp32 = 32,
}

impl ColorDepth {
    /// Get the raw bits-per-pixel value.
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Bitmap codec configuration (placeholder for future codec negotiation).
#[derive(Debug, Clone, Default)]
pub struct BitmapCodecConfig {
    /// Whether RemoteFX (RFX) codec is enabled.
    pub remotefx: bool,
    /// Whether NSCodec is enabled.
    pub nscodec: bool,
}

/// Compression configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompressionConfig {
    /// Whether bulk compression is enabled.
    pub enabled: bool,
}

/// A set of static virtual channels to request.
#[derive(Debug, Clone)]
pub struct StaticChannelSet {
    /// Channel definitions.
    channels: Vec<ChannelDef>,
}

impl StaticChannelSet {
    /// Create an empty channel set.
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
        }
    }

    /// Add a channel definition.
    pub fn push(&mut self, channel: ChannelDef) {
        self.channels.push(channel);
    }

    /// Get the channel definitions as a slice.
    pub fn as_slice(&self) -> &[ChannelDef] {
        &self.channels
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    /// Number of channels.
    pub fn len(&self) -> usize {
        self.channels.len()
    }

    /// Iterate over channel definitions.
    pub fn iter(&self) -> core::slice::Iter<'_, ChannelDef> {
        self.channels.iter()
    }

    /// Convert into the inner Vec.
    pub fn into_vec(self) -> Vec<ChannelDef> {
        self.channels
    }
}

impl Default for StaticChannelSet {
    fn default() -> Self {
        Self::new()
    }
}

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
    /// Azure AD authentication (PROTOCOL_RDSAAD).
    /// Requires pre-acquired OAuth2 access token and AAD nonce.
    AzureAd,
}

/// Azure AD authentication configuration.
///
/// The caller is responsible for the OAuth2 token acquisition (HTTP calls)
/// before constructing this config. The connector uses these values to
/// build the RDP Assertion (JWS) during the RDSAAD handshake.
#[derive(Debug, Clone)]
pub struct AadConfig {
    /// Pre-acquired OAuth2 RDP access token (PoP token from Azure AD).
    pub access_token: String,
    /// Resource URI / scope used for token acquisition.
    /// E.g., `ms-device-service://termsrv.wvd.microsoft.com/name/<host>/user_impersonation`
    pub resource_uri: String,
    /// AAD nonce from `POST /common/oauth2/token` with `grant_type=srv_challenge`.
    pub aad_nonce: String,
    /// RSA-2048 PoP private key for signing the RDP Assertion.
    pub pop_key: justrdp_core::rsa::RsaPrivateKey,
    /// RSA modulus (big-endian bytes) for JWK representation.
    pub pop_key_n: Vec<u8>,
    /// RSA public exponent (big-endian bytes) for JWK representation.
    pub pop_key_e: Vec<u8>,
    /// Unix timestamp (seconds since epoch) for the assertion.
    /// Caller must provide since no_std has no clock.
    pub timestamp: u64,
}

/// RDP connection configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Authentication credentials.
    pub credentials: Credentials,
    /// Domain name (None if none).
    pub domain: Option<String>,
    /// Desktop size in pixels.
    pub desktop_size: DesktopSize,
    /// Color depth.
    pub color_depth: ColorDepth,
    /// Keyboard type.
    pub keyboard_type: KeyboardType,
    /// Keyboard subtype. Default: 0.
    pub keyboard_subtype: u32,
    /// Keyboard layout (LCID). Default: 0x0409 (US English).
    pub keyboard_layout: u32,
    /// Client name sent to server.
    pub client_name: String,
    /// Client build number sent in version info. Default: 22621 (Windows 11 22H2).
    pub client_build: u32,
    /// Requested security protocol(s).
    pub security_protocol: SecurityProtocol,
    /// Performance flags.
    pub performance_flags: PerformanceFlags,
    /// Auto-reconnect cookie from a previous session (optional).
    pub auto_reconnect_cookie: Option<Vec<u8>>,
    /// Bitmap codec configuration.
    pub bitmap_codecs: BitmapCodecConfig,
    /// Compression configuration.
    pub compression: CompressionConfig,
    /// Static virtual channels to request.
    pub static_channels: StaticChannelSet,
    /// RDP cookie for load balancing (optional).
    pub cookie: Option<String>,
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
    /// Azure AD authentication configuration.
    /// Must be provided when auth_mode is AzureAd.
    pub aad_config: Option<AadConfig>,
}

impl Config {
    /// Create a builder with the given credentials.
    pub fn builder(username: &str, password: &str) -> ConfigBuilder {
        ConfigBuilder {
            config: Config {
                credentials: Credentials {
                    username: String::from(username),
                    password: String::from(password),
                },
                domain: None,
                desktop_size: DesktopSize::new(1024, 768),
                color_depth: ColorDepth::Bpp16,
                keyboard_type: KeyboardType::IbmEnhanced,
                keyboard_subtype: 0,
                keyboard_layout: 0x0409,
                client_name: String::new(),
                client_build: 22621,
                security_protocol: SecurityProtocol::SSL.union(SecurityProtocol::HYBRID),
                performance_flags: PerformanceFlags::from_bits(0),
                auto_reconnect_cookie: None,
                bitmap_codecs: BitmapCodecConfig::default(),
                compression: CompressionConfig::default(),
                static_channels: StaticChannelSet::new(),
                cookie: None,
                auth_mode: AuthMode::Password,
                kerberos_token: None,
                device_kerberos_token: None,
                client_random: None,
                aad_config: None,
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
        self.config.domain = Some(String::from(domain));
        self
    }

    /// Set the desktop resolution.
    pub fn desktop_size(mut self, width: u16, height: u16) -> Self {
        self.config.desktop_size = DesktopSize::new(width, height);
        self
    }

    /// Set the color depth.
    pub fn color_depth(mut self, depth: ColorDepth) -> Self {
        self.config.color_depth = depth;
        self
    }

    /// Set the keyboard layout (LCID).
    pub fn keyboard_layout(mut self, layout: u32) -> Self {
        self.config.keyboard_layout = layout;
        self
    }

    /// Set the keyboard type.
    pub fn keyboard_type(mut self, kb_type: KeyboardType) -> Self {
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
        self.config.static_channels.push(ChannelDef::new(name, options));
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

    /// Enable RemoteFX bitmap codec.
    pub fn remotefx(mut self, enabled: bool) -> Self {
        self.config.bitmap_codecs.remotefx = enabled;
        self
    }

    /// Enable NSCodec bitmap codec.
    pub fn nscodec(mut self, enabled: bool) -> Self {
        self.config.bitmap_codecs.nscodec = enabled;
        self
    }

    /// Enable bulk compression.
    pub fn compression(mut self, enabled: bool) -> Self {
        self.config.compression.enabled = enabled;
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

    /// Enable Azure AD authentication (PROTOCOL_RDSAAD).
    ///
    /// The caller must pre-acquire the OAuth2 access token, AAD nonce,
    /// and generate the RSA-2048 PoP key pair before calling this method.
    pub fn azure_ad(mut self, config: AadConfig) -> Self {
        self.config.auth_mode = AuthMode::AzureAd;
        self.config.security_protocol = SecurityProtocol::SSL.union(SecurityProtocol::AAD);
        self.config.aad_config = Some(config);
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

    /// Set the auto-reconnect cookie from a previous session.
    pub fn auto_reconnect_cookie(mut self, cookie: Vec<u8>) -> Self {
        self.config.auto_reconnect_cookie = Some(cookie);
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
