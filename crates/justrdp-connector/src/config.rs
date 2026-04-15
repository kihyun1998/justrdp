#![forbid(unsafe_code)]

//! Connection configuration.

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use justrdp_pdu::gcc::client::ChannelDef;
use justrdp_pdu::rdp::client_info::PerformanceFlags;
use justrdp_pdu::rdp::finalization::TS_MONITOR_PRIMARY;
use justrdp_pdu::x224::SecurityProtocol;

/// Opaque Auto-Reconnect Cookie received from the server (MS-RDPBCGR 2.2.4.2).
///
/// Stores `LogonId` and `ArcRandomBits` from `ARC_SC_PRIVATE_PACKET`.
/// Pass this to `ConfigBuilder::auto_reconnect_cookie()` to enable automatic reconnection.
///
/// `Debug` redacts `arc_random_bits` to prevent accidental secret leakage in logs.
#[derive(Clone, PartialEq, Eq)]
pub struct ArcCookie {
    /// Session ID from the server's ARC_SC_PRIVATE_PACKET.
    pub logon_id: u32,
    /// 16-byte random key used to compute the HMAC-MD5 SecurityVerifier.
    pub arc_random_bits: [u8; 16],
}

impl core::fmt::Debug for ArcCookie {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArcCookie")
            .field("logon_id", &self.logon_id)
            .field("arc_random_bits", &"[REDACTED]")
            .finish()
    }
}

impl ArcCookie {
    /// Construct an `ArcCookie` from the (logon_id, arc_random_bits) pair extracted
    /// from a server `SaveSessionInfoData::arc_random()` call.
    ///
    /// # Reconnect flow
    /// ```ignore
    /// use justrdp_session::ActiveStageOutput;
    /// use justrdp_connector::ArcCookie;
    ///
    /// for output in session.process(&frame)? {
    ///     if let ActiveStageOutput::SaveSessionInfo { data } = output {
    ///         if let Some((logon_id, arc_random_bits)) = data.arc_random() {
    ///             let cookie = ArcCookie::new(logon_id, arc_random_bits);
    ///             store_cookie_for_reconnect(cookie);
    ///         }
    ///     }
    /// }
    /// // Later, on disconnect:
    /// let new_config = previous_config.to_builder()
    ///     .auto_reconnect_cookie(stored_cookie)
    ///     .build();
    /// let connector = ClientConnector::new(new_config);
    /// // Drive the new connector through the connection sequence...
    /// ```
    pub fn new(logon_id: u32, arc_random_bits: [u8; 16]) -> Self {
        Self { logon_id, arc_random_bits }
    }
}

/// Authentication credentials.
#[derive(Clone)]
pub struct Credentials {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
}

impl core::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
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

/// Monitor configuration for multi-monitor support (MS-RDPBCGR 2.2.1.3.6, 2.2.1.3.9).
///
/// Each monitor defines a rectangular region in virtual desktop coordinates.
/// The primary monitor's upper-left corner must be at (0, 0). Other monitors
/// use signed coordinates relative to the primary (negative values allowed for
/// monitors to the left or above).
///
/// Coordinates are **inclusive**: a 1920×1080 monitor at origin has
/// `left=0, top=0, right=1919, bottom=1079`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorConfig {
    /// X-coordinate of upper-left corner (signed, relative to primary).
    pub left: i32,
    /// Y-coordinate of upper-left corner (signed, relative to primary).
    pub top: i32,
    /// X-coordinate of lower-right corner (inclusive).
    pub right: i32,
    /// Y-coordinate of lower-right corner (inclusive).
    pub bottom: i32,
    /// Whether this is the primary monitor. Exactly one monitor must be primary.
    pub is_primary: bool,
    /// Physical width in millimeters (0 = unknown, server ignores < 10 or > 10000).
    pub physical_width_mm: u32,
    /// Physical height in millimeters (0 = unknown, server ignores < 10 or > 10000).
    pub physical_height_mm: u32,
    /// Display orientation in degrees: 0, 90, 180, or 270.
    pub orientation: u32,
    /// Desktop scale factor percentage (100–500). Default: 100.
    pub desktop_scale_factor: u32,
    /// Device scale factor percentage: 100, 140, or 180. Default: 100.
    pub device_scale_factor: u32,
}

impl MonitorConfig {
    /// Create a primary monitor at origin with the given dimensions.
    ///
    /// Width and height are in pixels. Coordinates are set to
    /// `(0, 0, width-1, height-1)` with default scale factors.
    /// Values exceeding 32766 are rejected at connect time by the connector.
    pub fn primary(width: u32, height: u32) -> Self {
        Self {
            left: 0,
            top: 0,
            right: width.saturating_sub(1).min(i32::MAX as u32) as i32,
            bottom: height.saturating_sub(1).min(i32::MAX as u32) as i32,
            is_primary: true,
            physical_width_mm: 0,
            physical_height_mm: 0,
            orientation: 0,
            desktop_scale_factor: 100,
            device_scale_factor: 100,
        }
    }

    /// Create a secondary monitor at the given position.
    ///
    /// Values exceeding 32766 are rejected at connect time by the connector.
    pub fn secondary(left: i32, top: i32, width: u32, height: u32) -> Self {
        let w = width.saturating_sub(1).min(i32::MAX as u32) as i32;
        let h = height.saturating_sub(1).min(i32::MAX as u32) as i32;
        Self {
            left,
            top,
            right: left.saturating_add(w),
            bottom: top.saturating_add(h),
            is_primary: false,
            physical_width_mm: 0,
            physical_height_mm: 0,
            orientation: 0,
            desktop_scale_factor: 100,
            device_scale_factor: 100,
        }
    }

    /// Set the physical dimensions in millimeters.
    pub fn with_physical_size(mut self, width_mm: u32, height_mm: u32) -> Self {
        self.physical_width_mm = width_mm;
        self.physical_height_mm = height_mm;
        self
    }

    /// Set the display orientation.
    ///
    /// Valid values per MS-RDPBCGR 2.2.1.3.10.1:
    /// 0 (landscape), 90 (portrait), 180 (landscape flipped), 270 (portrait flipped).
    ///
    /// # Panics
    ///
    /// Panics if `degrees` is not one of 0, 90, 180, 270.
    pub fn with_orientation(mut self, degrees: u32) -> Self {
        assert!(
            matches!(degrees, 0 | 90 | 180 | 270),
            "orientation must be 0, 90, 180, or 270 (got {degrees})"
        );
        self.orientation = degrees;
        self
    }

    /// Set the DPI scale factors.
    ///
    /// Per MS-RDPBCGR 2.2.1.3.10.1:
    /// - `desktop_scale`: 100–500 (percentage)
    /// - `device_scale`: 100, 140, or 180 (percentage)
    ///
    /// # Panics
    ///
    /// Panics if values are out of spec range.
    pub fn with_scale(mut self, desktop_scale: u32, device_scale: u32) -> Self {
        assert!(
            (100..=500).contains(&desktop_scale),
            "desktop_scale_factor must be 100–500 (got {desktop_scale})"
        );
        assert!(
            matches!(device_scale, 100 | 140 | 180),
            "device_scale_factor must be 100, 140, or 180 (got {device_scale})"
        );
        self.desktop_scale_factor = desktop_scale;
        self.device_scale_factor = device_scale;
        self
    }
    /// Convert to display-control–compatible fields for `DisplayControlClient::set_monitor_layout()`.
    ///
    /// Returns `(flags, left, top, width, height, physical_width, physical_height,
    /// orientation, desktop_scale_factor, device_scale_factor)` matching the
    /// MS-RDPEDISP 2.2.2.2.1 `DISPLAYCONTROL_MONITOR_LAYOUT` entry layout.
    ///
    /// The bounding-box coordinates (left/top/right/bottom) are converted to
    /// left/top + width/height as used by the DisplayControl protocol.
    pub fn to_display_layout_fields(&self) -> (u32, i32, i32, u32, u32, u32, u32, u32, u32, u32) {
        let flags = if self.is_primary { TS_MONITOR_PRIMARY } else { 0 };
        let width = (self.right as i64 - self.left as i64 + 1).clamp(0, u32::MAX as i64) as u32;
        let height = (self.bottom as i64 - self.top as i64 + 1).clamp(0, u32::MAX as i64) as u32;
        (
            flags,
            self.left,
            self.top,
            width,
            height,
            self.physical_width_mm,
            self.physical_height_mm,
            self.orientation,
            self.desktop_scale_factor,
            self.device_scale_factor,
        )
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
#[derive(Clone)]
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

impl core::fmt::Debug for AadConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AadConfig")
            .field("access_token", &"[REDACTED]")
            .field("resource_uri", &self.resource_uri)
            .field("aad_nonce", &"[REDACTED]")
            .field("pop_key", &"[REDACTED]")
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

/// RDP connection configuration.
#[derive(Clone)]
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
    /// When set, the connector computes an HMAC-MD5 SecurityVerifier and includes
    /// an ARC_CS_PRIVATE_PACKET in the Client Info PDU (MS-RDPBCGR 5.5).
    pub auto_reconnect_cookie: Option<ArcCookie>,
    /// Bitmap codec configuration.
    pub bitmap_codecs: BitmapCodecConfig,
    /// Compression configuration.
    pub compression: CompressionConfig,
    /// Static virtual channels to request.
    pub static_channels: StaticChannelSet,
    /// RDP cookie for load balancing (optional, "Cookie: mstshash=" form).
    pub cookie: Option<String>,
    /// X.224 routing token from a Server Redirection PDU
    /// (`LB_LOAD_BALANCE_INFO`, MS-RDPBCGR 2.2.13.1).
    ///
    /// When set, the connector emits the bytes verbatim as the X.224
    /// Connection Request `routingToken` field instead of the
    /// `Cookie: mstshash=` form. Takes priority over the `cookie` field.
    /// Set this on the *new* connection after consuming a redirect PDU.
    pub routing_token: Option<Vec<u8>>,
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
    /// Opaque PK-encrypted password blob from a Server Redirection PDU
    /// (`LB_PASSWORD_IS_PK_ENCRYPTED`, MS-RDPBCGR 2.2.13.1).
    ///
    /// When set, the RDSTLS authentication request sends these bytes
    /// verbatim as the `Password` field instead of the cleartext password.
    /// The client never decrypts this blob — it is passed through to the
    /// target RD Session Host which decrypts it with its private key.
    pub redirection_password_blob: Option<Vec<u8>>,
    /// Redirection GUID from a Server Redirection PDU
    /// (`LB_REDIRECTION_GUID`, MS-RDPBCGR 2.2.13.1).
    ///
    /// Sent in the RDSTLS authentication request when
    /// `redirection_password_blob` is present.
    pub redirection_guid: Option<Vec<u8>>,
    /// Multi-monitor layout (MS-RDPBCGR 2.2.1.3.6).
    ///
    /// When two or more monitors are configured, CS_MONITOR and CS_MONITOR_EX
    /// GCC blocks are sent during the Basic Settings Exchange. The connector
    /// overrides the negotiated desktop dimensions with the bounding rectangle
    /// of all monitors; the `desktop_size` field itself is not modified.
    ///
    /// When empty (default), single-monitor mode is used with `desktop_size`.
    pub monitors: Vec<MonitorConfig>,
    /// Wall-clock budget for the connect phase: TCP connect, TLS
    /// handshake, CredSSP / NLA, BasicSettingsExchange, and connection
    /// finalization. The blocking runtime applies this as both the
    /// `TcpStream::connect_timeout` budget and the read/write timeout
    /// used during every handshake PDU exchange. Once the connector
    /// transitions into the active session pump the timeout is
    /// cleared so steady-state reads can block indefinitely waiting
    /// for the next frame.
    ///
    /// Default: 30 seconds.
    pub connect_timeout: Duration,
}

impl core::fmt::Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("credentials", &self.credentials)
            .field("domain", &self.domain)
            .field("desktop_size", &self.desktop_size)
            .field("color_depth", &self.color_depth)
            .field("keyboard_type", &self.keyboard_type)
            .field("keyboard_layout", &self.keyboard_layout)
            .field("client_name", &self.client_name)
            .field("security_protocol", &self.security_protocol)
            .field("auth_mode", &self.auth_mode)
            .field("routing_token", &self.routing_token.as_ref().map(|t| t.len()))
            .field("redirection_password_blob", &self.redirection_password_blob.as_ref().map(|_| "[REDACTED]"))
            .field("redirection_guid", &self.redirection_guid)
            .field("monitors", &self.monitors)
            .finish_non_exhaustive()
    }
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
                routing_token: None,
                auth_mode: AuthMode::Password,
                kerberos_token: None,
                device_kerberos_token: None,
                client_random: None,
                aad_config: None,
                redirection_password_blob: None,
                redirection_guid: None,
                monitors: Vec::new(),
                connect_timeout: Duration::from_secs(30),
            },
        }
    }
}

/// Builder for [`Config`].
pub struct ConfigBuilder {
    pub(crate) config: Config,
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

    /// Set the X.224 routing token from a Server Redirection PDU.
    ///
    /// When set, the connector uses the bytes verbatim as the
    /// `routingToken` field of the X.224 Connection Request, taking
    /// priority over [`cookie`](Self::cookie).
    pub fn routing_token(mut self, token: Vec<u8>) -> Self {
        self.config.routing_token = Some(token);
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
    ///
    /// The connector will compute the HMAC-MD5 SecurityVerifier and include an
    /// ARC_CS_PRIVATE_PACKET in the Client Info PDU during reconnection.
    pub fn auto_reconnect_cookie(mut self, cookie: ArcCookie) -> Self {
        self.config.auto_reconnect_cookie = Some(cookie);
        self
    }

    /// Set the client random for Standard RDP Security (32 bytes, must be cryptographic random).
    pub fn client_random(mut self, random: [u8; 32]) -> Self {
        self.config.client_random = Some(random);
        self
    }

    /// Add a monitor to the multi-monitor layout.
    ///
    /// When two or more monitors are configured, CS_MONITOR and CS_MONITOR_EX
    /// blocks are sent during the GCC Basic Settings Exchange. The bounding
    /// rectangle of all monitors replaces the `desktop_size` setting.
    pub fn monitor(mut self, config: MonitorConfig) -> Self {
        self.config.monitors.push(config);
        self
    }

    /// Set the full multi-monitor layout, replacing any previously added monitors.
    pub fn monitors(mut self, configs: Vec<MonitorConfig>) -> Self {
        self.config.monitors = configs;
        self
    }

    /// Set the PK-encrypted password blob from a Server Redirection PDU.
    ///
    /// When set, the RDSTLS authentication request sends these bytes as
    /// the opaque password field. Also switches the security protocol to
    /// RDSTLS automatically.
    pub fn redirection_password_blob(mut self, blob: Vec<u8>) -> Self {
        self.config.redirection_password_blob = Some(blob);
        self.config.security_protocol = SecurityProtocol::RDSTLS;
        self
    }

    /// Set the redirection GUID from a Server Redirection PDU.
    pub fn redirection_guid(mut self, guid: Vec<u8>) -> Self {
        self.config.redirection_guid = Some(guid);
        self
    }

    /// Set the wall-clock budget for the connect phase (TCP + TLS +
    /// CredSSP + BasicSettings + Finalization). The runtime applies
    /// this as `TcpStream::connect_timeout` and as the read/write
    /// timeout for every handshake PDU; it is cleared once the
    /// session pump begins so steady-state reads can block forever.
    ///
    /// Default: 30 seconds.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Apply settings from a parsed `.rdp` file.
    ///
    /// Maps the fields Windows `mstsc.exe` stores in `.rdp` files onto the
    /// connector [`Config`]. Credentials are **not** touched — `.rdp` files
    /// cannot carry passwords, and the username/password supplied to
    /// [`Config::builder`] takes precedence. Pass the file's `username`
    /// through the builder explicitly if you want it to override.
    ///
    /// Unmapped fields (Gateway, RemoteApp, smart-sizing, etc.) are
    /// silently ignored — the caller can still set those manually via
    /// dedicated builder methods. See [`rdpfile`](crate::rdpfile) for the
    /// complete mapping table and helpers to extract the server address.
    #[cfg(feature = "alloc")]
    pub fn apply_rdp_file(self, file: &justrdp_rdpfile::RdpFile) -> Self {
        crate::rdpfile::apply_to_builder(self, file)
    }

    /// Build the configuration.
    pub fn build(self) -> Config {
        self.config
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn connect_timeout_default_is_30s() {
        let config = Config::builder("u", "p").build();
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
    }

    #[test]
    fn connect_timeout_builder_sets_value() {
        let config = Config::builder("u", "p")
            .connect_timeout(Duration::from_secs(5))
            .build();
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
    }

    #[test]
    fn connect_timeout_accepts_zero() {
        // Zero means "non-blocking / immediate failure" per
        // std::net::TcpStream::connect_timeout documentation; the
        // builder must not reject it.
        let config = Config::builder("u", "p")
            .connect_timeout(Duration::ZERO)
            .build();
        assert_eq!(config.connect_timeout, Duration::ZERO);
    }
}
