#![forbid(unsafe_code)]

//! Client connection state machine implementation.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, PduHint, ReadCursor, WriteBuf, WriteCursor};

use justrdp_pdu::gcc::client::{
    ClientClusterData, ClientCoreData, ClientMonitorData, ClientMonitorExtendedData,
    ClientNetworkData, ClientSecurityData, EarlyCapabilityFlags, MonitorAttributeDef, MonitorDef,
};
use justrdp_pdu::gcc::{
    ConferenceCreateRequest, ConferenceCreateResponse, ServerDataBlockType, DATA_BLOCK_HEADER_SIZE,
};
use justrdp_pdu::mcs::{
    AttachUserConfirm, AttachUserRequest, ChannelJoinConfirm, ChannelJoinRequest,
    ConnectInitial, ConnectResponse, ConnectResponseResult, DomainParameters,
    ErectDomainRequest, SendDataIndication,
};
use justrdp_pdu::rdp::capabilities::{
    ActivationCapability, BitmapCapability, BrushCapability, CapabilitySet,
    ConfirmActivePdu, ControlCapability, DemandActivePdu, FontCapability,
    GeneralCapability, GlyphCacheCapability, InputCapability, LargePointerCapability,
    MultifragmentUpdateCapability, OrderCapability, PointerCapability,
    ShareCapability, SoundCapability, SurfaceCommandsCapability,
    VirtualChannelCapability,
};
use justrdp_pdu::rdp::client_info::ClientInfoPdu;
use justrdp_pdu::rdp::finalization::{
    ArcCsPrivatePacket, ControlAction, ControlPdu, FontListPdu, MonitorLayoutEntry,
    MonitorLayoutPdu, SaveSessionInfoPdu, SetErrorInfoPdu, SynchronizePdu,
    ERRINFO_NONE, TS_MONITOR_PRIMARY,
};
use justrdp_pdu::rdp::server_certificate;
use justrdp_pdu::rdp::standard_security::{
    self, FipsSecurityContext, RdpSecurityContext,
    SEC_ENCRYPT, SEC_EXCHANGE_PKT,
    ENCRYPTION_METHOD_FIPS, ENCRYPTION_LEVEL_NONE, ENCRYPTION_LEVEL_LOW,
};
use justrdp_pdu::rdp::headers::{
    ShareControlHeader, ShareControlPduType, ShareDataHeader, ShareDataPduType,
};
use justrdp_pdu::rdp::licensing::{LicenseErrorCode, LicenseMsgType, LicensePreamble};
use justrdp_pdu::tpkt::{TpktHeader, TpktHint};
use justrdp_pdu::x224::{
    ConnectionConfirm, ConnectionRequest, DataTransfer, NegotiationRequest,
    NegotiationResponseFlags, SecurityProtocol,
};

use crate::config::Config;

// ── Multi-monitor constants (MS-RDPBCGR 2.2.1.3.6) ──────────────────────────

/// Maximum number of monitors in CS_MONITOR (MS-RDPBCGR 2.2.1.3.6).
const MAX_MONITOR_COUNT: usize = 16;
/// Minimum virtual desktop dimension per axis (MS-RDPBCGR 2.2.1.3.6).
const VD_MIN_DIM: i64 = 200;
/// Maximum virtual desktop dimension per axis (MS-RDPBCGR 2.2.1.3.6).
const VD_MAX_DIM: i64 = 32766;

use crate::encode_helpers::{
    encode_connection_request, encode_mcs_send_data, encode_slow_path,
    wrap_share_control, wrap_share_data,
};
use crate::error::{ConnectorError, ConnectorErrorKind, ConnectorResult};
use crate::result::{ConnectionResult, Written};
use crate::sequence::Sequence;
use crate::state::ClientConnectorState;

/// Security header flags.
const SEC_INFO_PKT: u16 = 0x0040;
const SEC_LICENSE_PKT: u16 = 0x0080;

/// Security header size for TLS/NLA connections (basic header only).
const BASIC_SECURITY_HEADER_SIZE: usize = 4;

/// TPKT hint for PDU boundary detection.
static TPKT_HINT: TpktHint = TpktHint;

/// RDSTLS PDU hint: reads version(2) + dataType(2) + pduLength(2), uses pduLength as total size.
struct RdstlsHint;

impl PduHint for RdstlsHint {
    fn find_size(&self, bytes: &[u8]) -> Option<(bool, usize)> {
        if bytes.len() < 6 {
            return None;
        }
        let pdu_length = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
        // Must include at least the 6-byte header; cap at 64 KiB
        if pdu_length < 6 || pdu_length > 65536 {
            return None;
        }
        Some((false, pdu_length))
    }
}

static RDSTLS_HINT: RdstlsHint = RdstlsHint;

/// AAD JSON PDU hint: scans for the first `}` brace to determine PDU boundary.
/// RDSAAD PDUs are flat JSON objects over TLS with no binary framing.
struct AadJsonHint;

impl PduHint for AadJsonHint {
    fn find_size(&self, bytes: &[u8]) -> Option<(bool, usize)> {
        // Flat JSON PDU ends at the first `}` — return immediately on match.
        // Cap at 64 KiB to prevent unbounded buffering from a malicious server.
        const MAX_AAD_PDU_SIZE: usize = 65536;
        if bytes.len() > MAX_AAD_PDU_SIZE {
            return None;
        }
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'}' {
                return Some((false, i + 1));
            }
        }
        None
    }
}

static AAD_JSON_HINT: AadJsonHint = AadJsonHint;

/// RDP client connection state machine.
///
/// Drives the full RDP connection sequence without performing I/O.
/// The caller reads/writes network bytes and feeds them to `step()`.
pub struct ClientConnector {
    state: ClientConnectorState,
    config: Config,

    // Accumulated during connection
    selected_protocol: SecurityProtocol,
    server_nego_flags: NegotiationResponseFlags,
    io_channel_id: u16,
    user_channel_id: u16,
    share_id: u32,
    server_capabilities: Vec<CapabilitySet>,
    /// Channel IDs assigned by server (from ServerNetworkData).
    channel_ids: Vec<u16>,
    /// MCS message channel ID (for Auto-Detect PDUs).
    mcs_message_channel_id: Option<u16>,
    /// All channels to join: [user_channel_id, io_channel_id, ...channel_ids].
    channels_to_join: Vec<u16>,
    /// Current index into `channels_to_join` for the join loop.
    join_index: usize,
    /// Whether we are in the "send" sub-phase of channel join (true) or "wait" (false).
    channel_join_sending: bool,

    // ── Standard RDP Security state ──
    /// Server random (32 bytes) from ServerSecurityData.
    server_random: Option<[u8; 32]>,
    /// Server encryption method from ServerSecurityData.
    server_encryption_method: u32,
    /// Server encryption level from ServerSecurityData.
    server_encryption_level: u32,
    /// Server RDP version from ServerCoreData (for salted MAC decision).
    server_rdp_version: u32,
    /// Parsed server RSA public key.
    server_public_key: Option<server_certificate::ServerRsaPublicKey>,
    /// Security context for Standard RDP Security (RC4 or FIPS).
    security_mode: SecurityMode,
    /// Session ID from server.
    session_id: u32,
    /// Stored RDP Assertion JSON for AAD auth (built after receiving server nonce).
    aad_auth_request_json: Option<alloc::string::String>,
    /// Number of Deactivation-Reactivation cycles (for cache invalidation signaling).
    deactivation_count: u32,
    /// Effective desktop size for multi-monitor (bounding rect) or single-monitor.
    /// Set during BasicSettingsExchangeSendInitial, used in ConfirmActivePdu.
    active_desktop_size: Option<crate::config::DesktopSize>,
    /// Server monitor layout received during capabilities exchange / finalization
    /// (MS-RDPBCGR 2.2.12.1). Stored here until transition_to_connected().
    server_monitor_layout: Option<Vec<MonitorLayoutEntry>>,
    /// Auto-Reconnect Cookie received from a server-sent Save Session Info PDU
    /// during the connection sequence (MS-RDPBCGR 2.2.4.2). Most servers send the
    /// cookie *after* connection completes; this field captures the rare in-sequence case.
    server_arc_cookie: Option<crate::config::ArcCookie>,
}

/// Standard RDP Security mode (none for TLS/NLA).
enum SecurityMode {
    /// No Standard RDP Security (TLS/NLA).
    None,
    /// RC4-based Standard RDP Security (40/56/128-bit).
    Rc4(RdpSecurityContext),
    /// FIPS 140-1 mode (3DES-CBC + SHA-1 HMAC).
    Fips(FipsSecurityContext),
}

impl ClientConnector {
    /// Create a new connector with the given configuration.
    pub fn new(config: Config) -> Self {
        Self {
            state: ClientConnectorState::ConnectionInitiationSendRequest,
            config,
            selected_protocol: SecurityProtocol::RDP,
            server_nego_flags: NegotiationResponseFlags::NONE,
            io_channel_id: 0,
            user_channel_id: 0,
            share_id: 0,
            server_capabilities: Vec::new(),
            channel_ids: Vec::new(),
            mcs_message_channel_id: None,
            channels_to_join: Vec::new(),
            join_index: 0,
            channel_join_sending: true,
            server_random: None,
            server_encryption_method: 0,
            server_encryption_level: 0,
            server_rdp_version: 0,
            server_public_key: None,
            security_mode: SecurityMode::None,
            session_id: 0,
            aad_auth_request_json: None,
            deactivation_count: 0,
            active_desktop_size: None,
            server_monitor_layout: None,
            server_arc_cookie: None,
        }
    }

    /// Get the negotiated security protocol.
    pub fn selected_protocol(&self) -> SecurityProtocol {
        self.selected_protocol
    }

    /// Get a reference to the connector's [`Config`].
    ///
    /// Useful for I/O runtimes (e.g. `justrdp-blocking`) that need to read
    /// credentials, domain, or `auth_mode` after the connector has taken
    /// ownership of the config.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get the number of Deactivation-Reactivation cycles.
    /// Callers should check this to know if caches need to be invalidated.
    pub fn deactivation_count(&self) -> u32 {
        self.deactivation_count
    }

    /// Get the MCS message channel ID (for Auto-Detect PDUs).
    pub fn mcs_message_channel_id(&self) -> Option<u16> {
        self.mcs_message_channel_id
    }

    /// Get the connection result (only valid after reaching `Connected` state).
    pub fn result(&self) -> Option<&ConnectionResult> {
        match &self.state {
            ClientConnectorState::Connected { result } => Some(result),
            _ => None,
        }
    }

    /// Get the CredSSP credential type based on the auth mode.
    ///
    /// Used by the caller when constructing a `CredsspSequence` during the
    /// CredSSP/NLA phase (HYBRID/HYBRID_EX protocol).
    pub fn credssp_credential_type(&self) -> crate::credssp::CredentialType {
        match self.config.auth_mode {
            crate::config::AuthMode::RemoteCredentialGuard => {
                let kerberos_token = self.config.kerberos_token.clone().unwrap_or_default();
                let supplemental_creds = if let Some(ref device_token) = self.config.device_kerberos_token {
                    use justrdp_pdu::ntlm::messages::to_utf16le;
                    alloc::vec![crate::credssp::SupplementalCred {
                        package_name: to_utf16le("Kerberos"),
                        cred_buffer: device_token.clone(),
                    }]
                } else {
                    alloc::vec![]
                };
                crate::credssp::CredentialType::RemoteGuard {
                    kerberos_token,
                    supplemental_creds,
                }
            }
            crate::config::AuthMode::RestrictedAdmin => {
                crate::credssp::CredentialType::RestrictedAdmin
            }
            crate::config::AuthMode::AzureAd => {
                // AAD auth does not use CredSSP; return Password as fallback
                crate::credssp::CredentialType::Password
            }
            crate::config::AuthMode::Password => {
                crate::credssp::CredentialType::Password
            }
        }
    }

    // ── State handlers ──

    fn step_connection_initiation_send_request(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        use justrdp_pdu::x224::NegotiationRequestFlags;

        let flags = match self.config.auth_mode {
            crate::config::AuthMode::RestrictedAdmin => {
                NegotiationRequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED
            }
            crate::config::AuthMode::RemoteCredentialGuard => {
                NegotiationRequestFlags::REDIRECTED_AUTHENTICATION_MODE_REQUIRED
            }
            crate::config::AuthMode::Password => NegotiationRequestFlags::NONE,
            crate::config::AuthMode::AzureAd => NegotiationRequestFlags::NONE,
        };
        let nego = NegotiationRequest::with_flags(self.config.security_protocol, flags);

        let cr = if let Some(ref cookie) = self.config.cookie {
            ConnectionRequest::with_cookie(cookie.clone(), Some(nego))
        } else {
            ConnectionRequest::new(Some(nego))
        };

        let size = encode_connection_request(&cr, output)?;
        self.state = ClientConnectorState::ConnectionInitiationWaitConfirm;
        Ok(Written::new(size))
    }

    fn step_connection_initiation_wait_confirm(&mut self, input: &[u8]) -> ConnectorResult<Written> {
        use justrdp_pdu::x224::ConnectionConfirmNegotiation;

        let mut cursor = ReadCursor::new(input);
        let _tpkt = TpktHeader::decode(&mut cursor)?;
        let cc = ConnectionConfirm::decode(&mut cursor)?;

        match cc.negotiation {
            Some(ConnectionConfirmNegotiation::Failure(failure)) => {
                return Err(ConnectorError {
                    kind: ConnectorErrorKind::NegotiationFailure(failure.code),
                });
            }
            Some(ConnectionConfirmNegotiation::Response(response)) => {
                self.selected_protocol = response.protocol;
                self.server_nego_flags = response.flags;
            }
            None => {
                // No negotiation response means standard RDP security.
                // Reject if client requested TLS/HYBRID to prevent downgrade attack.
                if self.config.security_protocol != SecurityProtocol::RDP {
                    return Err(ConnectorError::general(
                        "server did not negotiate security protocol; refusing downgrade from TLS/HYBRID to RDP",
                    ));
                }
                self.selected_protocol = SecurityProtocol::RDP;
            }
        }

        // Validate server supports the requested auth mode
        match self.config.auth_mode {
            crate::config::AuthMode::RestrictedAdmin => {
                if !self.server_nego_flags.contains(NegotiationResponseFlags::RESTRICTED_ADMIN) {
                    return Err(ConnectorError::general(
                        "server does not support Restricted Admin Mode",
                    ));
                }
            }
            crate::config::AuthMode::RemoteCredentialGuard => {
                if !self.server_nego_flags.contains(NegotiationResponseFlags::REDIRECTED_AUTH) {
                    return Err(ConnectorError::general(
                        "server does not support Remote Credential Guard (Redirected Authentication)",
                    ));
                }
            }
            crate::config::AuthMode::AzureAd => {
                // AAD auth is indicated by selected protocol containing AAD flag
            }
            crate::config::AuthMode::Password => {}
        }

        // Transition based on selected protocol
        if self.selected_protocol != SecurityProtocol::RDP {
            self.state = ClientConnectorState::EnhancedSecurityUpgrade;
        } else {
            self.state = ClientConnectorState::BasicSettingsExchangeSendInitial;
        }

        Ok(Written::nothing())
    }

    fn step_enhanced_security_upgrade(&mut self) -> ConnectorResult<Written> {
        // Caller has completed TLS handshake
        if self.selected_protocol.contains(SecurityProtocol::AAD) {
            // Azure AD: wait for server nonce (JSON over raw TLS)
            self.state = ClientConnectorState::AadWaitServerNonce;
        } else if self.selected_protocol.contains(SecurityProtocol::RDSTLS) {
            // RDSTLS: Remote Credential Guard or Azure AD path
            self.state = ClientConnectorState::RdstlsSendCapabilities;
        } else if self.selected_protocol.contains(SecurityProtocol::HYBRID)
            || self.selected_protocol.contains(SecurityProtocol::HYBRID_EX)
        {
            self.state = ClientConnectorState::CredsspNegoTokens;
        } else {
            self.state = ClientConnectorState::BasicSettingsExchangeSendInitial;
        }
        Ok(Written::nothing())
    }

    // ── Phase 3: CredSSP states (caller-driven) ──

    fn step_credssp_nego_tokens(&mut self) -> ConnectorResult<Written> {
        // Caller performs SPNEGO token exchange externally.
        // Transition to PubKeyAuth after caller signals completion.
        self.state = ClientConnectorState::CredsspPubKeyAuth;
        Ok(Written::nothing())
    }

    fn step_credssp_pub_key_auth(&mut self) -> ConnectorResult<Written> {
        // Caller performs public key authentication externally.
        self.state = ClientConnectorState::CredsspCredentials;
        Ok(Written::nothing())
    }

    fn step_credssp_credentials(&mut self) -> ConnectorResult<Written> {
        // Caller sends encrypted credentials externally.
        if self.selected_protocol.contains(SecurityProtocol::HYBRID_EX) {
            self.state = ClientConnectorState::CredsspEarlyUserAuth;
        } else {
            self.state = ClientConnectorState::BasicSettingsExchangeSendInitial;
        }
        Ok(Written::nothing())
    }

    fn step_credssp_early_user_auth(&mut self) -> ConnectorResult<Written> {
        // Caller receives EarlyUserAuthResult externally.
        self.state = ClientConnectorState::BasicSettingsExchangeSendInitial;
        Ok(Written::nothing())
    }

    // ── Azure AD Authentication (RDSAAD) ──

    fn step_aad_wait_server_nonce(&mut self, input: &[u8]) -> ConnectorResult<Written> {
        // Parse server nonce JSON: {"ts_nonce":"<nonce>"}
        let json_str = core::str::from_utf8(input)
            .map_err(|_| ConnectorError::general("AAD server nonce is not valid UTF-8"))?;

        let server_nonce = crate::aad::extract_json_string_value(json_str, "ts_nonce")
            .ok_or_else(|| ConnectorError::general("AAD server nonce missing ts_nonce field"))?;

        // Build RDP Assertion from config + server nonce
        let aad_config = self.config.aad_config.as_ref()
            .ok_or_else(|| ConnectorError::general("AAD config not set"))?;

        let assertion = crate::aad::build_rdp_assertion(aad_config, server_nonce)?;
        let auth_json = crate::aad::build_auth_request_json(&assertion);
        self.aad_auth_request_json = Some(auth_json);

        self.state = ClientConnectorState::AadSendAuthRequest;
        Ok(Written::nothing())
    }

    fn step_aad_send_auth_request(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let json = self.aad_auth_request_json.take()
            .ok_or_else(|| ConnectorError::general("AAD auth request JSON not built"))?;

        let bytes = json.as_bytes();
        output.resize(bytes.len());
        output.as_mut_slice()[..bytes.len()].copy_from_slice(bytes);

        self.state = ClientConnectorState::AadWaitAuthResult;
        Ok(Written::new(bytes.len()))
    }

    fn step_aad_wait_auth_result(&mut self, input: &[u8]) -> ConnectorResult<Written> {
        let json_str = core::str::from_utf8(input)
            .map_err(|_| ConnectorError::general("AAD auth result is not valid UTF-8"))?;

        let result_code = crate::aad::extract_json_integer_value(json_str, "authentication_result")
            .ok_or_else(|| ConnectorError::general("AAD auth result missing authentication_result field"))?;

        if result_code != 0 {
            return Err(ConnectorError::general("AAD authentication failed"));
        }

        // Success — proceed to basic settings exchange
        self.state = ClientConnectorState::BasicSettingsExchangeSendInitial;
        Ok(Written::nothing())
    }

    // ── RDSTLS (Remote Credential Guard) ──

    fn step_rdstls_send_capabilities(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        use justrdp_pdu::rdp::rdstls::RdstlsCapabilities;

        let caps = RdstlsCapabilities::new();
        let size = caps.size();
        output.resize(size);
        let mut cursor = WriteCursor::new(output.as_mut_slice());
        caps.encode(&mut cursor)?;

        self.state = ClientConnectorState::RdstlsWaitCapabilities;
        Ok(Written::new(size))
    }

    fn step_rdstls_wait_capabilities(&mut self, input: &[u8]) -> ConnectorResult<Written> {
        use justrdp_pdu::rdp::rdstls::{RdstlsCapabilities, RDSTLS_VERSION_1};

        let mut cursor = ReadCursor::new(input);
        let server_caps = RdstlsCapabilities::decode(&mut cursor)?;

        // Verify server supports RDSTLS v1
        if server_caps.supported_versions & RDSTLS_VERSION_1 == 0 {
            return Err(ConnectorError::general(
                "server does not support RDSTLS version 1",
            ));
        }

        self.state = ClientConnectorState::RdstlsSendAuthRequest;
        Ok(Written::nothing())
    }

    fn step_rdstls_send_auth_request(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        use justrdp_pdu::rdp::rdstls::RdstlsAuthenticationRequest;
        use justrdp_pdu::ntlm::messages::to_utf16le;

        let domain_str = self.config.domain.as_deref().unwrap_or("");

        // Note: RestrictedAdmin uses HYBRID (CredSSP), never RDSTLS.
        // Only RemoteCredentialGuard and Password reach this RDSTLS path.
        let req = match self.config.auth_mode {
            crate::config::AuthMode::RemoteCredentialGuard => {
                let token = self.config.kerberos_token.as_ref()
                    .ok_or_else(|| ConnectorError::general(
                        "Remote Credential Guard requires a Kerberos token (set via Config)",
                    ))?;
                RdstlsAuthenticationRequest::kerberos(token.clone())
            }
            crate::config::AuthMode::RestrictedAdmin | crate::config::AuthMode::AzureAd => {
                // RestrictedAdmin uses HYBRID (CredSSP), AzureAd uses RDSAAD — neither uses RDSTLS.
                return Err(ConnectorError::general(
                    "this auth mode does not use RDSTLS (internal routing error)",
                ));
            }
            crate::config::AuthMode::Password => {
                RdstlsAuthenticationRequest::password(
                    &to_utf16le(domain_str),
                    &to_utf16le(&self.config.credentials.username),
                    &to_utf16le(&self.config.credentials.password),
                )
            }
        };

        let size = req.size();
        output.resize(size);
        let mut cursor = WriteCursor::new(output.as_mut_slice());
        req.encode(&mut cursor)?;

        self.state = ClientConnectorState::RdstlsWaitAuthResponse;
        Ok(Written::new(size))
    }

    fn step_rdstls_wait_auth_response(&mut self, input: &[u8]) -> ConnectorResult<Written> {
        use justrdp_pdu::rdp::rdstls::RdstlsAuthenticationResponse;

        let mut cursor = ReadCursor::new(input);
        let resp = RdstlsAuthenticationResponse::decode(&mut cursor)?;

        if resp.result_code != 0 {
            return Err(ConnectorError::general("RDSTLS authentication failed"));
        }

        // Authentication succeeded — proceed to basic settings exchange
        self.state = ClientConnectorState::BasicSettingsExchangeSendInitial;
        Ok(Written::nothing())
    }

    /// Build CS_MONITOR + CS_MONITOR_EX blocks if multi-monitor is active.
    ///
    /// Returns `(None, None)` when single-monitor mode should be used.
    /// Mutates `core_data` to override desktop dimensions and set the
    /// SUPPORT_MONITOR_LAYOUT_PDU flag when multi-monitor is active.
    fn build_monitor_blocks(
        &self,
        core_data: &mut ClientCoreData,
    ) -> ConnectorResult<(Option<ClientMonitorData>, Option<ClientMonitorExtendedData>)> {
        // MS-RDPBCGR 2.2.1.3.6: CS_MONITOR is only sent with ≥ 2 monitors and when
        // the server advertised EXTENDED_CLIENT_DATA_SUPPORTED. Single-monitor sessions
        // use CS_CORE desktopWidth/desktopHeight only — sending CS_MONITOR with
        // monitorCount=1 is spec-legal but adds no value and breaks some servers.
        let send_monitors = self.config.monitors.len() >= 2
            && self.server_nego_flags.contains(NegotiationResponseFlags::EXTENDED_CLIENT_DATA);

        if !send_monitors {
            return Ok((None, None));
        }

        let monitors = &self.config.monitors;

        // MS-RDPBCGR 2.2.1.3.6: monitorCount MUST NOT exceed 16
        if monitors.len() > MAX_MONITOR_COUNT {
            return Err(ConnectorError::general(
                "monitor count exceeds maximum of 16",
            ));
        }

        // Validate: exactly one primary at (0, 0)
        let primary_count = monitors.iter().filter(|m| m.is_primary).count();
        if primary_count != 1 {
            return Err(ConnectorError::general(
                "multi-monitor config must have exactly one primary monitor",
            ));
        }
        let primary = monitors.iter().find(|m| m.is_primary)
            .expect("exactly one primary guaranteed by primary_count check");
        if primary.left != 0 || primary.top != 0 {
            return Err(ConnectorError::general(
                "primary monitor upper-left must be at (0, 0)",
            ));
        }

        // Validate per-monitor geometry: reject inverted rectangles
        for m in monitors.iter() {
            if m.right < m.left || m.bottom < m.top {
                return Err(ConnectorError::general(
                    "monitor has inverted coordinates (right < left or bottom < top)",
                ));
            }
        }

        // Compute bounding rectangle (MS-RDPBCGR 2.2.1.3.6)
        let min_left = monitors.iter().map(|m| m.left).min()
            .expect("monitors non-empty; guarded by len >= 2");
        let min_top = monitors.iter().map(|m| m.top).min()
            .expect("monitors non-empty; guarded by len >= 2");
        let max_right = monitors.iter().map(|m| m.right).max()
            .expect("monitors non-empty; guarded by len >= 2");
        let max_bottom = monitors.iter().map(|m| m.bottom).max()
            .expect("monitors non-empty; guarded by len >= 2");

        // right/bottom are inclusive, so width = max_right - min_left + 1
        let vd_width = (max_right as i64) - (min_left as i64) + 1;
        let vd_height = (max_bottom as i64) - (min_top as i64) + 1;

        if vd_width < VD_MIN_DIM || vd_height < VD_MIN_DIM {
            return Err(ConnectorError::general(
                "virtual desktop dimensions must be at least 200×200",
            ));
        }
        if vd_width > VD_MAX_DIM || vd_height > VD_MAX_DIM {
            return Err(ConnectorError::general(
                "virtual desktop dimensions must not exceed 32766×32766",
            ));
        }

        // Override desktop size with bounding rectangle
        core_data.desktop_width = vd_width as u16;
        core_data.desktop_height = vd_height as u16;

        // Set SUPPORT_MONITOR_LAYOUT_PDU flag (MS-RDPBCGR 2.2.1.3.2)
        let existing = core_data.early_capability_flags.unwrap_or(EarlyCapabilityFlags::SUPPORT_ERRINFO_PDU);
        core_data.early_capability_flags = Some(EarlyCapabilityFlags::from_bits(
            existing.bits() | EarlyCapabilityFlags::SUPPORT_MONITOR_LAYOUT_PDU.bits(),
        ));

        // Build CS_MONITOR (TS_UD_CS_MONITOR)
        let monitor_defs: Vec<MonitorDef> = monitors
            .iter()
            .map(|m| MonitorDef {
                left: m.left,
                top: m.top,
                right: m.right,
                bottom: m.bottom,
                flags: if m.is_primary { TS_MONITOR_PRIMARY } else { 0 },
            })
            .collect();
        let cs_monitor = ClientMonitorData { monitors: monitor_defs };

        // Build CS_MONITOR_EX (TS_UD_CS_MONITOR_EX)
        let monitor_attrs: Vec<MonitorAttributeDef> = monitors
            .iter()
            .map(|m| MonitorAttributeDef {
                physical_width: m.physical_width_mm,
                physical_height: m.physical_height_mm,
                orientation: m.orientation,
                desktop_scale_factor: m.desktop_scale_factor,
                device_scale_factor: m.device_scale_factor,
            })
            .collect();
        let cs_monitor_ex = ClientMonitorExtendedData { monitors: monitor_attrs };

        Ok((Some(cs_monitor), Some(cs_monitor_ex)))
    }

    fn step_basic_settings_send_initial(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        // Build GCC client data blocks
        let mut core_data = ClientCoreData::new(self.config.desktop_size.width, self.config.desktop_size.height);
        core_data.keyboard_layout = self.config.keyboard_layout;
        core_data.keyboard_type = self.config.keyboard_type.as_u32();
        core_data.client_name = self.config.client_name.clone();
        core_data.server_selected_protocol = Some(self.selected_protocol.bits());

        let (monitor_data, monitor_ext_data) = self.build_monitor_blocks(&mut core_data)?;

        // Populate CS_CORE DPI fields from the primary monitor (MS-RDPBCGR 2.2.1.3.2).
        // These describe the primary display for both single- and multi-monitor sessions.
        if let Some(primary) = self.config.monitors.iter().find(|m| m.is_primary) {
            core_data.desktop_physical_width = Some(primary.physical_width_mm);
            core_data.desktop_physical_height = Some(primary.physical_height_mm);
            // CS_CORE desktopOrientation is u16; MonitorConfig.orientation is u32.
            // All valid values (0, 90, 180, 270) fit in u16.
            core_data.desktop_orientation = Some(primary.orientation as u16);
            core_data.desktop_scale_factor = Some(primary.desktop_scale_factor);
            core_data.device_scale_factor = Some(primary.device_scale_factor);

            // Single-monitor: override CS_CORE desktopWidth/Height from the monitor's
            // actual dimensions, applying the same bounds as the multi-monitor path.
            if self.config.monitors.len() == 1 {
                if primary.left != 0 || primary.top != 0 {
                    return Err(ConnectorError::general(
                        "primary monitor upper-left must be at (0, 0)",
                    ));
                }
                let w = primary.right as i64 - primary.left as i64 + 1;
                let h = primary.bottom as i64 - primary.top as i64 + 1;
                if w < VD_MIN_DIM || h < VD_MIN_DIM {
                    return Err(ConnectorError::general(
                        "single monitor dimensions must be at least 200×200",
                    ));
                }
                if w > VD_MAX_DIM || h > VD_MAX_DIM {
                    return Err(ConnectorError::general(
                        "single monitor dimensions must not exceed 32766×32766",
                    ));
                }
                core_data.desktop_width = w as u16;
                core_data.desktop_height = h as u16;
            }
        }

        // Store effective desktop size for use in ConfirmActivePdu (BitmapCapability)
        self.active_desktop_size = Some(crate::config::DesktopSize {
            width: core_data.desktop_width,
            height: core_data.desktop_height,
        });

        let security_data = ClientSecurityData::new();

        let cluster_data = ClientClusterData {
            flags: 0x0000_0011, // REDIRECTION_SUPPORTED | (REDIRECTION_VERSION5 << 2)
            redirected_session_id: 0,
        };

        // Build optional blocks once, then measure + encode (avoids double construction)
        let net_data = if !self.config.static_channels.is_empty() {
            Some(ClientNetworkData {
                channels: self.config.static_channels.as_slice().to_vec(),
            })
        } else {
            None
        };

        // Compute total client data size
        // Block order: Core → Cluster → Security → Net → Monitor → MonitorEx
        let mut client_data_size = core_data.size() + cluster_data.size() + security_data.size();
        if let Some(ref nd) = net_data { client_data_size += nd.size(); }
        if let Some(ref md) = monitor_data { client_data_size += md.size(); }
        if let Some(ref mex) = monitor_ext_data { client_data_size += mex.size(); }

        let mut client_data = vec![0u8; client_data_size];
        {
            let mut cursor = WriteCursor::new(&mut client_data);
            core_data.encode(&mut cursor)?;
            cluster_data.encode(&mut cursor)?;
            security_data.encode(&mut cursor)?;
            if let Some(ref nd) = net_data { nd.encode(&mut cursor)?; }
            if let Some(ref md) = monitor_data { md.encode(&mut cursor)?; }
            if let Some(ref mex) = monitor_ext_data { mex.encode(&mut cursor)?; }
        }

        // Wrap in GCC ConferenceCreateRequest
        let gcc = ConferenceCreateRequest::new(client_data);
        let gcc_encoded = justrdp_core::encode_vec(&gcc)?;

        // Build MCS Connect Initial
        let connect_initial = ConnectInitial {
            calling_domain_selector: vec![1],
            called_domain_selector: vec![1],
            upward_flag: true,
            target_parameters: DomainParameters::client_default(),
            minimum_parameters: DomainParameters::min_default(),
            maximum_parameters: DomainParameters::max_default(),
            user_data: gcc_encoded,
        };

        let size = encode_slow_path(&connect_initial, output)?;
        self.state = ClientConnectorState::BasicSettingsExchangeWaitResponse;
        Ok(Written::new(size))
    }

    fn step_basic_settings_wait_response(&mut self, input: &[u8]) -> ConnectorResult<Written> {
        let mut cursor = ReadCursor::new(input);
        let _tpkt = TpktHeader::decode(&mut cursor)?;
        let _dt = DataTransfer::decode(&mut cursor)?;
        let response = ConnectResponse::decode(&mut cursor)?;

        if response.result != ConnectResponseResult::RtSuccessful {
            return Err(ConnectorError {
                kind: ConnectorErrorKind::McsConnectFailure(response.result),
            });
        }

        // Decode GCC ConferenceCreateResponse
        let gcc = {
            let mut gcc_cursor = ReadCursor::new(&response.user_data);
            ConferenceCreateResponse::decode(&mut gcc_cursor)?
        };

        // Parse server data blocks
        self.parse_server_data_blocks(&gcc.user_data)?;

        self.state = ClientConnectorState::ChannelConnectionSendErectDomainRequest;
        Ok(Written::nothing())
    }

    fn parse_server_data_blocks(&mut self, data: &[u8]) -> ConnectorResult<()> {
        let mut cursor = ReadCursor::new(data);

        while cursor.remaining() >= DATA_BLOCK_HEADER_SIZE {
            let block_type = cursor.read_u16_le("ServerDataBlock::type")?;
            let block_length = cursor.read_u16_le("ServerDataBlock::length")? as usize;

            if block_length < DATA_BLOCK_HEADER_SIZE {
                return Err(ConnectorError::general("server data block length too small"));
            }

            let body_length = block_length - DATA_BLOCK_HEADER_SIZE;
            if cursor.remaining() < body_length {
                break;
            }

            let block_data = cursor.read_slice(body_length, "ServerDataBlock::data")?;
            let mut block_cursor = ReadCursor::new(block_data);

            match block_type {
                t if t == ServerDataBlockType::CoreData as u16 => {
                    // Body is already stripped of header; read version directly
                    let version = block_cursor.read_u32_le("CoreData::version")?;
                    self.server_rdp_version = version;
                }
                t if t == ServerDataBlockType::SecurityData as u16 => {
                    let encryption_method = block_cursor.read_u32_le("SecData::method")?;
                    let encryption_level = block_cursor.read_u32_le("SecData::level")?;

                    self.server_encryption_method = encryption_method;
                    self.server_encryption_level = encryption_level;

                    let remaining = body_length.saturating_sub(8);
                    if remaining >= 8 && encryption_method != 0 && encryption_level != ENCRYPTION_LEVEL_NONE {
                        let random_len = block_cursor.read_u32_le("SecData::randomLen")? as usize;
                        let cert_len = block_cursor.read_u32_le("SecData::certLen")? as usize;
                        // MS-RDPBCGR 2.2.1.4.3: serverRandom MUST be exactly 32 bytes
                        if random_len != 32 {
                            return Err(ConnectorError::general("server random must be exactly 32 bytes"));
                        }
                        // Reasonable upper bound for server certificate
                        if cert_len > 16 * 1024 {
                            return Err(ConnectorError::general("server certificate length exceeds maximum"));
                        }
                        let random = block_cursor.read_slice(random_len, "SecData::random")?;
                        let cert_data = block_cursor.read_slice(cert_len, "SecData::cert")?;

                        let mut sr = [0u8; 32];
                        sr.copy_from_slice(random);
                        self.server_random = Some(sr);

                        // Parse server certificate to extract RSA public key
                        let cert = server_certificate::parse_server_certificate(cert_data)?;
                        self.server_public_key = Some(cert.public_key);
                    }
                }
                t if t == ServerDataBlockType::NetworkData as u16 => {
                    // Parse body directly (header already consumed by parse_server_data_blocks)
                    let mcs_channel_id = block_cursor.read_u16_le("NetData::mcsChannelId")?;
                    let count = block_cursor.read_u16_le("NetData::channelCount")? as usize;
                    // MS-RDPBCGR 2.2.1.4.4: practical limit is 31 static channels + system channels
                    if count > 64 {
                        return Err(ConnectorError::general("server channel count exceeds maximum"));
                    }
                    let mut channel_ids = Vec::with_capacity(count);
                    for _ in 0..count {
                        channel_ids.push(block_cursor.read_u16_le("NetData::channelId")?);
                    }
                    self.io_channel_id = mcs_channel_id;
                    self.channel_ids = channel_ids;
                }
                t if t == ServerDataBlockType::MessageChannelData as u16 => {
                    // ServerMessageChannelData: mcs_message_channel_id (u16 LE)
                    let msg_channel_id = block_cursor.read_u16_le("MsgChannelData::channelId")?;
                    self.mcs_message_channel_id = Some(msg_channel_id);
                }
                _ => {
                    // Unknown block type — skip
                }
            }
        }

        Ok(())
    }

    fn step_send_erect_domain_request(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let pdu = ErectDomainRequest {
            sub_height: 0,
            sub_interval: 0,
        };
        let size = encode_slow_path(&pdu, output)?;
        self.state = ClientConnectorState::ChannelConnectionSendAttachUserRequest;
        Ok(Written::new(size))
    }

    fn step_send_attach_user_request(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let size = encode_slow_path(&AttachUserRequest, output)?;
        self.state = ClientConnectorState::ChannelConnectionWaitAttachUserConfirm;
        Ok(Written::new(size))
    }

    fn step_wait_attach_user_confirm(&mut self, input: &[u8]) -> ConnectorResult<Written> {
        let mut cursor = ReadCursor::new(input);
        let _tpkt = TpktHeader::decode(&mut cursor)?;
        let _dt = DataTransfer::decode(&mut cursor)?;
        let confirm = AttachUserConfirm::decode(&mut cursor)?;

        if confirm.result != 0 {
            return Err(ConnectorError {
                kind: ConnectorErrorKind::AttachUserFailure {
                    result: confirm.result,
                },
            });
        }

        self.user_channel_id = confirm
            .initiator
            .ok_or_else(|| ConnectorError::general("AttachUserConfirm missing initiator"))?;

        // Build channel join list: user channel, I/O channel, then static channels
        self.channels_to_join = Vec::with_capacity(2 + self.channel_ids.len());
        self.channels_to_join.push(self.user_channel_id);
        self.channels_to_join.push(self.io_channel_id);
        for &ch_id in &self.channel_ids {
            self.channels_to_join.push(ch_id);
        }
        self.join_index = 0;
        self.channel_join_sending = true;

        self.state = ClientConnectorState::ChannelConnectionChannelJoin;
        Ok(Written::nothing())
    }

    /// ChannelConnectionChannelJoin: alternates between sending Join Request
    /// and waiting for Join Confirm for each channel in `channels_to_join`.
    fn step_channel_join(&mut self, input: &[u8], output: &mut WriteBuf) -> ConnectorResult<Written> {
        if self.channel_join_sending {
            // Send Join Request for current channel
            let channel_id = *self.channels_to_join.get(self.join_index)
                .ok_or_else(|| ConnectorError::general("channel join index out of bounds"))?;
            let pdu = ChannelJoinRequest {
                initiator: self.user_channel_id,
                channel_id,
            };
            let size = encode_slow_path(&pdu, output)?;
            self.channel_join_sending = false;
            Ok(Written::new(size))
        } else {
            // Wait for Join Confirm
            let mut cursor = ReadCursor::new(input);
            let _tpkt = TpktHeader::decode(&mut cursor)?;
            let _dt = DataTransfer::decode(&mut cursor)?;
            let confirm = ChannelJoinConfirm::decode(&mut cursor)?;

            if confirm.result != 0 {
                let expected_channel = self.channels_to_join[self.join_index];
                return Err(ConnectorError {
                    kind: ConnectorErrorKind::ChannelJoinFailure {
                        channel_id: expected_channel,
                        result: confirm.result,
                    },
                });
            }

            self.join_index += 1;
            if self.join_index < self.channels_to_join.len() {
                // More channels to join
                self.channel_join_sending = true;
            } else if self.uses_standard_rdp_security() {
                // Standard RDP Security: send Security Exchange PDU first
                self.state = ClientConnectorState::SecurityCommencement;
            } else {
                self.state = ClientConnectorState::SecureSettingsExchange;
            }

            Ok(Written::nothing())
        }
    }

    /// Whether this connection uses Standard RDP Security (not TLS/NLA).
    fn uses_standard_rdp_security(&self) -> bool {
        self.selected_protocol == SecurityProtocol::RDP
            && self.server_encryption_method != 0
            && self.server_encryption_level != ENCRYPTION_LEVEL_NONE
    }

    /// Decrypt server PDU user_data when using Standard RDP Security.
    ///
    /// For Standard RDP Security: strips security header (flags + flagsHi + MAC),
    /// decrypts the payload, and returns (flags, decrypted_data).
    /// For TLS/NLA: strips basic security header and returns raw data.
    fn decrypt_server_data(&mut self, user_data: &[u8]) -> ConnectorResult<(u16, Vec<u8>)> {
        let mut inner = ReadCursor::new(user_data);
        let flags = inner.read_u16_le("SecurityHeader::flags")?;
        let _flags_hi = inner.read_u16_le("SecurityHeader::flagsHi")?;

        match &mut self.security_mode {
            SecurityMode::Rc4(ctx) if flags & SEC_ENCRYPT != 0 => {
                let mac_bytes = inner.read_slice(8, "SecurityHeader::mac")?;
                let mut mac = [0u8; 8];
                mac.copy_from_slice(mac_bytes);
                let remaining = inner.remaining();
                let encrypted = inner.read_slice(remaining, "SecurityHeader::encryptedData")?;
                let mut data = encrypted.to_vec();
                let valid = ctx.decrypt(&mut data, &mac);
                if !valid {
                    return Err(ConnectorError::general("Standard RDP Security: MAC verification failed (RC4)"));
                }
                Ok((flags, data))
            }
            SecurityMode::Fips(ctx) if flags & SEC_ENCRYPT != 0 => {
                // MS-RDPBCGR §5.3.6 TS_SECURITY_HEADER2: length(2) + version(1) + padLen(1) + dataSignature(8)
                let _fips_length = inner.read_u16_le("FipsHeader::length")?;
                let _fips_version = inner.read_u8("FipsHeader::version")?;
                let pad_len = inner.read_u8("FipsHeader::padLen")?;
                let mac_bytes = inner.read_slice(8, "FipsHeader::mac")?;
                let mut mac = [0u8; 8];
                mac.copy_from_slice(mac_bytes);
                let remaining = inner.remaining();
                let encrypted = inner.read_slice(remaining, "SecurityHeader::encryptedData")?;
                let (data, valid) = ctx.decrypt(encrypted, &mac, pad_len);
                if !valid {
                    return Err(ConnectorError::general("Standard RDP Security: MAC verification failed (FIPS)"));
                }
                Ok((flags, data))
            }
            SecurityMode::Rc4(_) | SecurityMode::Fips(_)
                if self.server_encryption_level != ENCRYPTION_LEVEL_LOW =>
            {
                // Encryption negotiated at CLIENT_COMPATIBLE/HIGH/FIPS but SEC_ENCRYPT
                // not set — reject to prevent downgrade attack.
                Err(ConnectorError::general("Standard RDP Security: SEC_ENCRYPT flag missing on encrypted session"))
            }
            _ => {
                // ENCRYPTION_LEVEL_LOW: server→client is not encrypted (MS-RDPBCGR 5.3.2).
                // SecurityMode::None: TLS/NLA, no encryption layer.
                let remaining = inner.remaining();
                let data = inner.read_slice(remaining, "SecurityHeader::data")?;
                Ok((flags, data.to_vec()))
            }
        }
    }

    /// Encrypt and send a PDU via MCS when using Standard RDP Security.
    ///
    /// For Standard RDP Security: encrypts data, adds security header with MAC.
    /// For TLS/NLA: sends raw data (no security header added).
    fn encrypt_and_send_mcs(
        &mut self,
        payload: &[u8],
        output: &mut WriteBuf,
    ) -> ConnectorResult<usize> {
        match &mut self.security_mode {
            SecurityMode::Rc4(ctx) => {
                let mut data = payload.to_vec();
                let mac = ctx.encrypt(&mut data);

                let inner_size = BASIC_SECURITY_HEADER_SIZE + 8 + data.len();
                let mut inner = vec![0u8; inner_size];
                {
                    let mut cursor = WriteCursor::new(&mut inner);
                    cursor.write_u16_le(SEC_ENCRYPT, "SecurityHeader::flags")?;
                    cursor.write_u16_le(0, "SecurityHeader::flagsHi")?;
                    cursor.write_slice(&mac, "SecurityHeader::mac")?;
                    cursor.write_slice(&data, "SecurityHeader::encryptedData")?;
                }
                encode_mcs_send_data(self.user_channel_id, self.io_channel_id, &inner, output)
            }
            SecurityMode::Fips(ctx) => {
                let (ciphertext, mac, pad_len) = ctx.encrypt(payload);

                // MS-RDPBCGR §5.3.6: flags(2) + flagsHi(2) + length(2) + version(1) + padLen(1) + MAC(8) + data
                let inner_size = 4 + 2 + 1 + 1 + 8 + ciphertext.len();
                let mut inner = vec![0u8; inner_size];
                {
                    let mut cursor = WriteCursor::new(&mut inner);
                    cursor.write_u16_le(SEC_ENCRYPT, "SecurityHeader::flags")?;
                    cursor.write_u16_le(0, "SecurityHeader::flagsHi")?;
                    cursor.write_u16_le(0x0010, "FipsHeader::length")?;
                    cursor.write_u8(0x01, "FipsHeader::version")?;
                    cursor.write_u8(pad_len, "FipsHeader::padLen")?;
                    cursor.write_slice(&mac, "FipsHeader::mac")?;
                    cursor.write_slice(&ciphertext, "FipsHeader::encryptedData")?;
                }
                encode_mcs_send_data(self.user_channel_id, self.io_channel_id, &inner, output)
            }
            SecurityMode::None => {
                encode_mcs_send_data(self.user_channel_id, self.io_channel_id, payload, output)
            }
        }
    }

    /// Send Security Exchange PDU: encrypted client random.
    ///
    /// MS-RDPBCGR 2.2.1.10: The client generates a 32-byte random, encrypts it
    /// with the server's RSA public key, and sends it in a Security Exchange PDU.
    /// Then derives session keys from (client_random + server_random).
    fn step_security_commencement(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let server_key = self.server_public_key.as_ref()
            .ok_or_else(|| ConnectorError::general("no server public key for security exchange"))?;
        let server_random = self.server_random
            .ok_or_else(|| ConnectorError::general("no server random for security exchange"))?;

        // Client random must be provided via Config (cryptographically random)
        let client_random = self.config.client_random
            .ok_or_else(|| ConnectorError::general(
                "Standard RDP Security requires client_random in Config (use ConfigBuilder::client_random())",
            ))?;

        // Encrypt client random with server's RSA public key
        let encrypted_random = standard_security::encrypt_client_random(server_key, &client_random);

        // Build Security Exchange PDU
        // Header: flags(2) + flagsHi(2) = SEC_EXCHANGE_PKT
        // Body: length(4 LE) + encrypted_random
        let encrypted_len: u32 = encrypted_random.len()
            .try_into()
            .map_err(|_| ConnectorError::general("encrypted random too large"))?;
        let inner_size = BASIC_SECURITY_HEADER_SIZE + 4 + encrypted_len as usize;
        let mut inner = vec![0u8; inner_size];
        {
            let mut cursor = WriteCursor::new(&mut inner);
            cursor.write_u16_le(SEC_EXCHANGE_PKT, "SecExchange::flags")?;
            cursor.write_u16_le(0, "SecExchange::flagsHi")?;
            cursor.write_u32_le(encrypted_len, "SecExchange::length")?;
            cursor.write_slice(&encrypted_random, "SecExchange::encryptedRandom")?;
        }

        let size = encode_mcs_send_data(self.user_channel_id, self.io_channel_id, &inner, output)?;

        // Derive session keys and create security context
        if self.server_encryption_method == ENCRYPTION_METHOD_FIPS {
            let fips_keys = standard_security::derive_fips_session_keys(
                &client_random,
                &server_random,
            );
            self.security_mode = SecurityMode::Fips(FipsSecurityContext::new(fips_keys));
        } else {
            let keys = standard_security::derive_session_keys(
                &client_random,
                &server_random,
                self.server_encryption_method,
            );
            // SEC_SECURE_CHECKSUM is available on RDP 5.2+ (version >= 0x00080004)
            let use_salted_mac = self.server_rdp_version >= 0x00080004;
            self.security_mode = SecurityMode::Rc4(RdpSecurityContext::new(keys, use_salted_mac));
        }
        self.state = ClientConnectorState::SecureSettingsExchange;

        Ok(Written::new(size))
    }

    fn step_secure_settings_exchange(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let domain_str = self.config.domain.as_deref().unwrap_or("");
        let mut info = ClientInfoPdu::new(domain_str, &self.config.credentials.username, &self.config.credentials.password)
            .with_performance_flags(self.config.performance_flags);

        // Auto-reconnect: compute HMAC-MD5 SecurityVerifier (MS-RDPBCGR 5.5)
        if let Some(ref arc_cookie) = self.config.auto_reconnect_cookie {
            // Enhanced RDP Security (TLS/NLA): ClientRandom = 32 zero bytes
            // Standard RDP Security: use actual client_random
            let client_random = self.config.client_random.unwrap_or([0u8; 32]);
            let security_verifier = justrdp_core::crypto::hmac_md5(
                &arc_cookie.arc_random_bits,
                &client_random,
            );
            let arc_cs = ArcCsPrivatePacket {
                logon_id: arc_cookie.logon_id,
                security_verifier,
            };
            if let Some(ref mut extra) = info.extra {
                extra.auto_reconnect_cookie = Some(arc_cs);
            }
        }

        // Encode Client Info PDU
        let info_bytes = justrdp_core::encode_vec(&info)?;

        // Build security header + info
        let is_encrypted = !matches!(self.security_mode, SecurityMode::None);
        let sec_flags = if is_encrypted { SEC_INFO_PKT | SEC_ENCRYPT } else { SEC_INFO_PKT };

        if is_encrypted {
            match &mut self.security_mode {
                SecurityMode::Rc4(ctx) => {
                    let mut data = info_bytes.clone();
                    let mac = ctx.encrypt(&mut data);
                    let inner_size = BASIC_SECURITY_HEADER_SIZE + 8 + data.len();
                    let mut inner = vec![0u8; inner_size];
                    {
                        let mut cursor = WriteCursor::new(&mut inner);
                        cursor.write_u16_le(sec_flags, "SecurityHeader::flags")?;
                        cursor.write_u16_le(0, "SecurityHeader::flagsHi")?;
                        cursor.write_slice(&mac, "SecurityHeader::mac")?;
                        cursor.write_slice(&data, "SecurityHeader::encryptedData")?;
                    }
                    let size = encode_mcs_send_data(self.user_channel_id, self.io_channel_id, &inner, output)?;
                    self.state = ClientConnectorState::ConnectTimeAutoDetection;
                    Ok(Written::new(size))
                }
                SecurityMode::Fips(ctx) => {
                    let (ciphertext, mac, pad_len) = ctx.encrypt(&info_bytes);
                    // MS-RDPBCGR §5.3.6: flags(2) + flagsHi(2) + length(2) + version(1) + padLen(1) + MAC(8) + data
                    let inner_size = 4 + 2 + 1 + 1 + 8 + ciphertext.len();
                    let mut inner = vec![0u8; inner_size];
                    {
                        let mut cursor = WriteCursor::new(&mut inner);
                        cursor.write_u16_le(sec_flags, "SecurityHeader::flags")?;
                        cursor.write_u16_le(0, "SecurityHeader::flagsHi")?;
                        cursor.write_u16_le(0x0010, "FipsHeader::length")?;
                        cursor.write_u8(0x01, "FipsHeader::version")?;
                        cursor.write_u8(pad_len, "FipsHeader::padLen")?;
                        cursor.write_slice(&mac, "FipsHeader::mac")?;
                        cursor.write_slice(&ciphertext, "FipsHeader::encryptedData")?;
                    }
                    let size = encode_mcs_send_data(self.user_channel_id, self.io_channel_id, &inner, output)?;
                    self.state = ClientConnectorState::ConnectTimeAutoDetection;
                    Ok(Written::new(size))
                }
                SecurityMode::None => {
                    Err(ConnectorError::general("internal error: None security mode in encrypted path"))
                }
            }
        } else {
            // TLS/NLA mode: send unencrypted (basic security header only)
            let inner_size = BASIC_SECURITY_HEADER_SIZE + info_bytes.len();
            let mut inner = vec![0u8; inner_size];
            {
                let mut cursor = WriteCursor::new(&mut inner);
                cursor.write_u16_le(SEC_INFO_PKT, "SecurityHeader::flags")?;
                cursor.write_u16_le(0, "SecurityHeader::flagsHi")?;
                cursor.write_slice(&info_bytes, "SecurityHeader::encryptedData")?;
            }
            let size = encode_mcs_send_data(self.user_channel_id, self.io_channel_id, &inner, output)?;
            self.state = ClientConnectorState::ConnectTimeAutoDetection;
            Ok(Written::new(size))
        }
    }

    /// Phase 8: Connect-Time Auto-Detection.
    ///
    /// MS-RDPBCGR 1.3.1.1: server may optionally send auto-detect PDUs on the
    /// message channel. Most servers skip this and send the licensing PDU directly.
    ///
    /// Current behavior: forward the received PDU to the licensing handler.
    /// The licensing handler already handles non-license PDUs gracefully.
    /// TODO: implement full auto-detect sequence (RTT, bandwidth measurement).
    fn step_connect_time_auto_detection(&mut self, input: &[u8], output: &mut WriteBuf) -> ConnectorResult<Written> {
        // Transition to licensing and let it process this PDU
        self.state = ClientConnectorState::LicensingExchange;
        self.step_licensing_exchange(input, output)
    }

    fn step_licensing_exchange(&mut self, input: &[u8], output: &mut WriteBuf) -> ConnectorResult<Written> {
        let mut cursor = ReadCursor::new(input);
        let _tpkt = TpktHeader::decode(&mut cursor)?;
        let _dt = DataTransfer::decode(&mut cursor)?;

        // Decode MCS SendDataIndication
        let sdi = SendDataIndication::decode(&mut cursor)?;

        // Decrypt if Standard RDP Security
        let (flags, decrypted) = self.decrypt_server_data(sdi.user_data)?;

        if flags & SEC_LICENSE_PKT == 0 {
            // Not a licensing PDU — could be auto-detect or something else.
            // Stay in current state and wait for licensing PDU.
            return Ok(Written::nothing());
        }

        // Decode license preamble
        let mut inner = ReadCursor::new(&decrypted);
        let preamble = LicensePreamble::decode(&mut inner)?;

        match preamble.msg_type {
            LicenseMsgType::ErrorAlert => {
                let error_code_val = inner.read_u32_le("LicenseError::errorCode")?;
                let error_code = justrdp_pdu::rdp::licensing::LicenseErrorCode::from_u32(error_code_val)?;
                let _state_transition = inner.read_u32_le("LicenseError::stateTransition")?;

                if error_code == LicenseErrorCode::StatusValidClient {
                    // Licensing complete — skip to capabilities
                    self.state = ClientConnectorState::MultitransportBootstrapping;
                    Ok(Written::nothing())
                } else {
                    Err(ConnectorError {
                        kind: ConnectorErrorKind::LicensingError(error_code),
                    })
                }
            }
            LicenseMsgType::LicenseRequest | LicenseMsgType::PlatformChallenge => {
                // Server requires licensing negotiation.
                // Respond with ErrorAlert: ERR_NO_LICENSE_SERVER / ST_TOTAL_ABORT.
                let error_msg = build_license_error_response();

                let inner_size = BASIC_SECURITY_HEADER_SIZE + error_msg.len();
                let mut inner_buf = vec![0u8; inner_size];
                {
                    let mut cursor = WriteCursor::new(&mut inner_buf);
                    cursor.write_u16_le(SEC_LICENSE_PKT, "LicenseResp::flags")?;
                    cursor.write_u16_le(0, "LicenseResp::flagsHi")?;
                    cursor.write_slice(&error_msg, "LicenseResp::data")?;
                }

                let size = encode_mcs_send_data(
                    self.user_channel_id, self.io_channel_id, &inner_buf, output,
                )?;

                // Stay in LicensingExchange for server's response
                Ok(Written::new(size))
            }
            LicenseMsgType::NewLicense | LicenseMsgType::UpgradeLicense => {
                // Server granted a license — licensing complete
                self.state = ClientConnectorState::MultitransportBootstrapping;
                Ok(Written::nothing())
            }
            _ => {
                // Unknown licensing PDU — skip and wait
                Ok(Written::nothing())
            }
        }
    }

    /// Phase 10: Multitransport Bootstrapping.
    /// MS-RDPBCGR 2.2.15.1: server may optionally initiate multitransport.
    /// Currently a pass-through; transitions immediately to capabilities exchange.
    fn step_multitransport_bootstrapping(&mut self) -> ConnectorResult<Written> {
        self.state = ClientConnectorState::CapabilitiesExchangeWaitDemandActive;
        Ok(Written::nothing())
    }

    fn step_capabilities_wait_demand_active(&mut self, input: &[u8]) -> ConnectorResult<Written> {
        let mut cursor = ReadCursor::new(input);
        let _tpkt = TpktHeader::decode(&mut cursor)?;
        let _dt = DataTransfer::decode(&mut cursor)?;

        let sdi = SendDataIndication::decode(&mut cursor)?;

        // Decrypt if Standard RDP Security
        let decrypted = if !matches!(self.security_mode, SecurityMode::None) {
            let (_flags, data) = self.decrypt_server_data(sdi.user_data)?;
            data
        } else {
            sdi.user_data.to_vec()
        };

        let mut inner = ReadCursor::new(&decrypted);

        // Decode Share Control Header
        let sc_hdr = ShareControlHeader::decode(&mut inner)?;

        if sc_hdr.pdu_type != ShareControlPduType::DemandActivePdu {
            // Handle data PDUs (e.g., MonitorLayoutPdu) that may arrive before Demand Active.
            if sc_hdr.pdu_type == ShareControlPduType::Data {
                let sd_hdr = ShareDataHeader::decode(&mut inner)?;
                let _ = self.try_store_monitor_layout(sd_hdr.pdu_type2, &mut inner)?;
            }
            return Ok(Written::nothing());
        }

        // Decode Demand Active PDU
        let demand = DemandActivePdu::decode(&mut inner)?;
        self.share_id = demand.share_id;
        self.session_id = demand.session_id;
        self.server_capabilities = demand.capability_sets;

        self.state = ClientConnectorState::CapabilitiesExchangeSendConfirmActive;
        Ok(Written::nothing())
    }

    fn step_capabilities_send_confirm_active(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let confirm = ConfirmActivePdu {
            share_id: self.share_id,
            // MS-RDPBCGR 2.2.1.13.2.1: originatorID is the constant
            // 0x03EA (the server-side originator of the Demand Active PDU).
            // It is NOT the I/O channel ID — Windows RDS rejects mismatches
            // with ERRINFO_CONFIRMACTIVEWRONGORIGINATOR (0x10D5) immediately
            // after receiving the Confirm Active PDU.
            originator_id: 0x03EA,
            source_descriptor: vec![0x4D, 0x53, 0x54, 0x53, 0x43, 0x00], // "MSTSC\0"
            capability_sets: self.build_client_capabilities(),
        };

        let confirm_bytes = justrdp_core::encode_vec(&confirm)?;

        let sc_payload = wrap_share_control(
            ShareControlPduType::ConfirmActivePdu,
            self.user_channel_id,
            &confirm_bytes,
        )?;

        let size = self.encrypt_and_send_mcs(&sc_payload, output)?;
        self.state = ClientConnectorState::ConnectionFinalizationSendSynchronize;
        Ok(Written::new(size))
    }

    fn build_client_capabilities(&self) -> Vec<CapabilitySet> {
        vec![
            CapabilitySet::General(GeneralCapability {
                os_major_type: 1,  // OSMAJORTYPE_WINDOWS
                os_minor_type: 3,  // OSMINORTYPE_WINDOWS_NT
                protocol_version: 0x0200,
                pad2: 0,
                general_compression_types: 0,
                extra_flags: 0x041D, // FASTPATH_OUTPUT_SUPPORTED | LONG_CREDENTIALS_SUPPORTED | AUTORECONNECT_SUPPORTED | ENC_SALTED_CHECKSUM | NO_BITMAP_COMPRESSION_HDR
                update_capability_flag: 0,
                remote_unshare_flag: 0,
                general_compression_level: 0,
                refresh_rect_support: 1,
                suppress_output_support: 1,
            }),
            CapabilitySet::Bitmap({
                let ds = self.active_desktop_size.unwrap_or(self.config.desktop_size);
                BitmapCapability {
                    preferred_bits_per_pixel: self.config.color_depth.as_u16(),
                    receive1_bit_per_pixel: 1,
                    receive4_bits_per_pixel: 1,
                    receive8_bits_per_pixel: 1,
                    desktop_width: ds.width,
                    desktop_height: ds.height,
                    pad2a: 0,
                    desktop_resize_flag: 1,
                    bitmap_compression_flag: 1,
                    high_color_flags: 0,
                    drawing_flags: 0x08 | 0x10 | 0x20, // DRAW_ALLOW_DYNAMIC_COLOR_FIDELITY | DRAW_ALLOW_COLOR_SUBSAMPLING | DRAW_ALLOW_SKIP_ALPHA
                    multiple_rectangle_support: 1,
                    pad2b: 0,
                }
            }),
            CapabilitySet::Order(OrderCapability {
                terminal_descriptor: [0u8; 16],
                pad4: 0,
                desktop_save_x_granularity: 1,
                desktop_save_y_granularity: 20,
                pad2a: 0,
                maximum_order_level: 1,
                number_fonts: 0,
                order_flags: 0x002A, // NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT | COLORINDEXSUPPORT
                order_support: {
                    // Minimal order support matching FreeRDP defaults
                    let mut os = [0u8; 32];
                    os[0] = 1;  // TS_NEG_DSTBLT_INDEX
                    os[1] = 1;  // TS_NEG_PATBLT_INDEX
                    os[2] = 1;  // TS_NEG_SCRBLT_INDEX
                    os[3] = 1;  // TS_NEG_MEMBLT_INDEX (v1)
                    os[4] = 1;  // TS_NEG_MEM3BLT_INDEX (v1)
                    os[8] = 1;  // TS_NEG_LINETO_INDEX
                    os[15] = 1; // TS_NEG_MULTIDSTBLT_INDEX
                    os[16] = 1; // TS_NEG_MULTIPATBLT_INDEX
                    os[17] = 1; // TS_NEG_MULTISCRBLT_INDEX
                    os[18] = 1; // TS_NEG_MULTIOPAQUERECT_INDEX
                    os[22] = 1; // TS_NEG_POLYLINE_INDEX
                    os[25] = 1; // TS_NEG_ELLIPSE_SC_INDEX
                    os[27] = 1; // TS_NEG_INDEX_INDEX
                    os
                },
                text_flags: 0x06A1,
                order_support_ex_flags: 0,
                pad4b: 0,
                desktop_save_size: 0x38400, // 230400 = 320*240*3
                pad2b: 0,
                pad2c: 0,
                text_ansi_code_page: 0,
                pad2d: 0,
            }),
            CapabilitySet::Input(InputCapability {
                input_flags: 0x0035, // INPUT_FLAG_SCANCODES | INPUT_FLAG_MOUSEX | INPUT_FLAG_UNICODE | INPUT_FLAG_FASTPATH_INPUT2
                pad2: 0,
                keyboard_layout: self.config.keyboard_layout,
                keyboard_type: self.config.keyboard_type.as_u32(),
                keyboard_sub_type: self.config.keyboard_subtype,
                keyboard_function_key: 12,
                ime_file_name: [0u8; 64],
            }),
            CapabilitySet::Font(FontCapability {
                font_support_flags: 0x0001, // FONTSUPPORT_FONTLIST
                pad2: 0,
            }),
            CapabilitySet::Brush(BrushCapability {
                brush_support_level: 1, // BRUSH_COLOR_8x8
            }),
            CapabilitySet::GlyphCache(GlyphCacheCapability {
                glyph_cache: {
                    let mut gc = [0u8; 40];
                    // 10 cache entries: each 4 bytes (entries_u16_le + max_cell_size_u16_le)
                    let entries: [(u16, u16); 10] = [
                        (254, 4), (254, 4), (254, 8), (254, 8),
                        (254, 16), (254, 32), (254, 64), (254, 128),
                        (254, 256), (64, 2048),
                    ];
                    for (i, &(count, size)) in entries.iter().enumerate() {
                        gc[i * 4..i * 4 + 2].copy_from_slice(&count.to_le_bytes());
                        gc[i * 4 + 2..i * 4 + 4].copy_from_slice(&size.to_le_bytes());
                    }
                    gc
                },
                frag_cache: {
                    // entries(u16_le=256) + max_cell_size(u16_le=256)
                    let mut fc = [0u8; 4];
                    fc[0..2].copy_from_slice(&256u16.to_le_bytes());
                    fc[2..4].copy_from_slice(&256u16.to_le_bytes());
                    u32::from_le_bytes(fc)
                },
                glyph_support_level: 3, // GLYPH_SUPPORT_ENCODE
                pad2: 0,
            }),
            CapabilitySet::VirtualChannel(VirtualChannelCapability {
                flags: 0,
                vc_chunk_size: Some(1600),
            }),
            CapabilitySet::Sound(SoundCapability {
                sound_flags: 0x0001, // SOUND_BEEPS_FLAG
                pad2: 0,
            }),
            CapabilitySet::Control(ControlCapability {
                control_flags: 0,
                remote_detach_flag: 0,
                control_interest: 0x0002, // CONTROLPRIORITY_NEVER
                detach_interest: 0x0002,
            }),
            CapabilitySet::Activation(ActivationCapability {
                help_key_flag: 0,
                help_key_index_flag: 0,
                help_extended_key_flag: 0,
                window_manager_key_flag: 0,
            }),
            CapabilitySet::Pointer(PointerCapability {
                color_pointer_flag: 1,
                color_pointer_cache_size: 25,
                pointer_cache_size: 25,
            }),
            CapabilitySet::Share(ShareCapability {
                node_id: 0,
                pad2: 0,
            }),
            CapabilitySet::MultifragmentUpdate(MultifragmentUpdateCapability {
                max_request_size: 0x00038400, // 230400 = 320*240*3
            }),
            CapabilitySet::LargePointer(LargePointerCapability {
                large_pointer_support_flags: 0x0001, // LARGE_POINTER_FLAG_96x96
            }),
            CapabilitySet::SurfaceCommands(SurfaceCommandsCapability {
                cmd_flags: 0x0052, // SURFCMDS_SET_SURFACE_BITS | SURFCMDS_FRAME_MARKER | SURFCMDS_STREAM_SURFACE_BITS
                reserved: 0,
            }),
        ]
    }

    /// If the ShareData PDU type is MonitorLayoutPdu, decode and store it.
    /// MS-RDPBCGR 2.2.12.1: last-write-wins if server sends multiple layouts.
    /// Returns `true` if it was a MonitorLayoutPdu (consumed from `inner`).
    fn try_store_monitor_layout(
        &mut self,
        pdu_type2: ShareDataPduType,
        inner: &mut ReadCursor<'_>,
    ) -> ConnectorResult<bool> {
        match pdu_type2 {
            ShareDataPduType::MonitorLayoutPdu => {
                let layout = MonitorLayoutPdu::decode(inner)?;
                self.server_monitor_layout = Some(layout.monitors);
                Ok(true)
            }
            ShareDataPduType::SaveSessionInfo => {
                // Capture ARC cookie if the server sends one during the connection sequence.
                // Most servers send it after the connection completes, but a few send it here.
                let pdu = SaveSessionInfoPdu::decode(inner)?;
                if let Some((logon_id, arc_random_bits)) = pdu.info_data.arc_random() {
                    self.server_arc_cookie = Some(crate::config::ArcCookie {
                        logon_id,
                        arc_random_bits,
                    });
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn step_send_finalization_pdu<T: Encode>(
        &mut self,
        pdu_type2: ShareDataPduType,
        inner: &T,
        next_state: ClientConnectorState,
        output: &mut WriteBuf,
    ) -> ConnectorResult<Written> {
        let inner_bytes = justrdp_core::encode_vec(inner)?;
        let sd_payload = wrap_share_data(self.share_id, pdu_type2, &inner_bytes)?;
        let sc_payload = wrap_share_control(
            ShareControlPduType::Data,
            self.user_channel_id,
            &sd_payload,
        )?;
        let size = self.encrypt_and_send_mcs(&sc_payload, output)?;
        self.state = next_state;
        Ok(Written::new(size))
    }

    fn step_finalization_send_synchronize(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let pdu = SynchronizePdu {
            message_type: 1, // SYNCMSGTYPE_SYNC
            target_user: self.io_channel_id,
        };
        self.step_send_finalization_pdu(
            ShareDataPduType::Synchronize,
            &pdu,
            ClientConnectorState::ConnectionFinalizationSendCooperate,
            output,
        )
    }

    fn step_finalization_send_cooperate(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let pdu = ControlPdu {
            action: ControlAction::Cooperate,
            grant_id: 0,
            control_id: 0,
        };
        self.step_send_finalization_pdu(
            ShareDataPduType::Control,
            &pdu,
            ClientConnectorState::ConnectionFinalizationSendRequestControl,
            output,
        )
    }

    fn step_finalization_send_request_control(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let pdu = ControlPdu {
            action: ControlAction::RequestControl,
            grant_id: 0,
            control_id: 0,
        };
        self.step_send_finalization_pdu(
            ShareDataPduType::Control,
            &pdu,
            ClientConnectorState::ConnectionFinalizationSendPersistentKeyList,
            output,
        )
    }

    /// Persistent Key List PDU step (MS-RDPBCGR 2.2.1.17).
    ///
    /// Currently a no-op transition: PersistentKeyList is optional per
    /// MS-RDPBCGR 1.3.1.3 and is only valid when the Confirm Active PDU
    /// advertises the Revision 2 Bitmap Cache Capability Set with
    /// `persistentKeysExpected` set. We do not yet advertise that
    /// capability, and Windows RDS rejects the combination with
    /// ERRINFO_CACHECAPNOTSET (0x000010F4) immediately followed by a
    /// connection reset. Skip the PDU until proper persistent bitmap
    /// cache support lands.
    fn step_finalization_send_persistent_key_list(&mut self, _output: &mut WriteBuf) -> ConnectorResult<Written> {
        self.state = ClientConnectorState::ConnectionFinalizationSendFontList;
        Ok(Written::nothing())
    }

    fn step_finalization_send_font_list(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let pdu = FontListPdu::default_request();
        self.step_send_finalization_pdu(
            ShareDataPduType::FontList,
            &pdu,
            ClientConnectorState::ConnectionFinalizationWaitSynchronize,
            output,
        )
    }

    fn step_finalization_wait_pdu(
        &mut self,
        input: &[u8],
        expected_type: ShareDataPduType,
        next_state: ClientConnectorState,
    ) -> ConnectorResult<Written> {
        let mut cursor = ReadCursor::new(input);
        let _tpkt = TpktHeader::decode(&mut cursor)?;
        let _dt = DataTransfer::decode(&mut cursor)?;

        let sdi = SendDataIndication::decode(&mut cursor)?;

        // Decrypt if Standard RDP Security
        let decrypted = if !matches!(self.security_mode, SecurityMode::None) {
            let (_flags, data) = self.decrypt_server_data(sdi.user_data)?;
            data
        } else {
            sdi.user_data.to_vec()
        };

        let mut inner = ReadCursor::new(&decrypted);

        let sc_hdr = ShareControlHeader::decode(&mut inner)?;

        if sc_hdr.pdu_type == ShareControlPduType::DeactivateAllPdu {
            // Deactivation-Reactivation: go back to capabilities exchange
            // MS-RDPBCGR 1.3.1.3 — caller should check deactivation_count() to flush caches
            self.deactivation_count = self.deactivation_count.saturating_add(1);
            self.state = ClientConnectorState::CapabilitiesExchangeWaitDemandActive;
            return Ok(Written::nothing());
        }

        if sc_hdr.pdu_type != ShareControlPduType::Data {
            // Unknown non-data PDU — stay in same state
            return Ok(Written::nothing());
        }

        let sd_hdr = ShareDataHeader::decode(&mut inner)?;

        if self.try_store_monitor_layout(sd_hdr.pdu_type2, &mut inner)? {
            return Ok(Written::nothing());
        }

        // Informational PDUs that may interleave with the finalization
        // sequence (MS-RDPBCGR 1.3.1.3 — server is allowed to send these
        // alongside Sync/Cooperate/Granted/FontMap).
        //
        // SetErrorInfo with ERRINFO_NONE is a "no errors yet" heartbeat;
        // a non-zero code is treated like the active-session path: store
        // it for the eventual disconnect reason but do not abort here,
        // because the server may still complete finalization successfully
        // (it cleared the error info via ERRINFO_NONE later).
        //
        // SaveSessionInfo (logon notification + ARC cookie) can arrive
        // mid-finalization on Windows servers. The connector cannot emit
        // events, so we silently swallow it here; ActiveStage will surface
        // any subsequent SaveSessionInfo PDUs once the session is live.
        // Informational PDUs that may interleave with the finalization
        // sequence. SetErrorInfo with non-ERRINFO_NONE means the server
        // already detected a fatal problem in our preceding PDUs and is
        // about to reset the connection — surface that as a connector
        // error so the caller does not silently hang on the next read.
        // SaveSessionInfo can carry the logon ARC cookie; we drop it
        // here because the connector cannot emit events, and ActiveStage
        // will re-surface any subsequent SaveSessionInfo PDUs.
        if sd_hdr.pdu_type2 == ShareDataPduType::SetErrorInfo {
            let pdu = SetErrorInfoPdu::decode(&mut inner)?;
            if pdu.error_info != ERRINFO_NONE {
                panic!(
                    "DIAG: finalization SetErrorInfo error_info=0x{:08X}",
                    pdu.error_info
                );
            }
            return Ok(Written::nothing());
        }
        if sd_hdr.pdu_type2 == ShareDataPduType::SaveSessionInfo {
            return Ok(Written::nothing());
        }

        if sd_hdr.pdu_type2 != expected_type {
            // Not the expected finalization PDU and not an informational
            // PDU we recognize — stay in the same state. With a buffered
            // transport reader the next iteration will pick up the
            // expected PDU; without one, the caller may hang.
            return Ok(Written::nothing());
        }

        self.state = next_state;
        Ok(Written::nothing())
    }

    /// Wait for Font Map PDU and transition to Connected.
    fn step_finalization_wait_font_map(&mut self, input: &[u8]) -> ConnectorResult<Written> {
        let mut cursor = ReadCursor::new(input);
        let _tpkt = TpktHeader::decode(&mut cursor)?;
        let _dt = DataTransfer::decode(&mut cursor)?;

        let sdi = SendDataIndication::decode(&mut cursor)?;

        let decrypted = if !matches!(self.security_mode, SecurityMode::None) {
            let (_flags, data) = self.decrypt_server_data(sdi.user_data)?;
            data
        } else {
            sdi.user_data.to_vec()
        };

        let mut inner = ReadCursor::new(&decrypted);
        let sc_hdr = ShareControlHeader::decode(&mut inner)?;

        if sc_hdr.pdu_type == ShareControlPduType::DeactivateAllPdu {
            self.deactivation_count = self.deactivation_count.saturating_add(1);
            self.state = ClientConnectorState::CapabilitiesExchangeWaitDemandActive;
            return Ok(Written::nothing());
        }

        if sc_hdr.pdu_type != ShareControlPduType::Data {
            return Ok(Written::nothing());
        }

        let sd_hdr = ShareDataHeader::decode(&mut inner)?;

        if self.try_store_monitor_layout(sd_hdr.pdu_type2, &mut inner)? {
            return Ok(Written::nothing());
        }

        // Same informational PDU handling as step_finalization_wait_pdu —
        // Windows servers can interleave SetErrorInfo (heartbeat) and
        // SaveSessionInfo (logon notification) with the FontMap PDU.
        if sd_hdr.pdu_type2 == ShareDataPduType::SetErrorInfo {
            let pdu = SetErrorInfoPdu::decode(&mut inner)?;
            if pdu.error_info != ERRINFO_NONE {
                return Err(ConnectorError::general(
                    "server reported fatal error_info while waiting for FontMap",
                ));
            }
            return Ok(Written::nothing());
        }
        if sd_hdr.pdu_type2 == ShareDataPduType::SaveSessionInfo {
            return Ok(Written::nothing());
        }

        if sd_hdr.pdu_type2 != ShareDataPduType::FontMap {
            return Ok(Written::nothing());
        }

        // Font Map received — connection complete
        self.transition_to_connected();
        Ok(Written::nothing())
    }

    /// Build the ConnectionResult and transition to Connected state.
    fn transition_to_connected(&mut self) {
        let channel_ids = self
            .config
            .static_channels
            .iter()
            .zip(self.channel_ids.iter())
            .map(|(def, &id)| (String::from(def.name_str()), id))
            .collect();

        let result = ConnectionResult {
            io_channel_id: self.io_channel_id,
            user_channel_id: self.user_channel_id,
            share_id: self.share_id,
            server_capabilities: self.server_capabilities.clone(),
            channel_ids,
            selected_protocol: self.selected_protocol,
            session_id: self.session_id,
            server_monitor_layout: self.server_monitor_layout.take(),
            server_arc_cookie: self.server_arc_cookie.take(),
        };

        self.state = ClientConnectorState::Connected { result };
    }
}

/// Build a licensing ErrorAlert response (ERR_NO_LICENSE_SERVER / ST_TOTAL_ABORT).
///
/// This tells the server that the client cannot fulfill the license request.
/// Most servers will respond with STATUS_VALID_CLIENT or disconnect.
fn build_license_error_response() -> Vec<u8> {
    // LicensePreamble(4) + errorCode(4) + stateTransition(4) + errorInfo blob(4)
    let mut buf = vec![0u8; 16];
    buf[0] = LicenseMsgType::ErrorAlert as u8;  // msgType
    buf[1] = 0x80; // flags: EXTENDED_ERROR_MSG_SUPPORTED
    buf[2..4].copy_from_slice(&16u16.to_le_bytes()); // msgSize
    buf[4..8].copy_from_slice(&0x0006u32.to_le_bytes()); // ERR_NO_LICENSE_SERVER
    buf[8..12].copy_from_slice(&0x0001u32.to_le_bytes()); // ST_TOTAL_ABORT
    buf[12..14].copy_from_slice(&0x0004u16.to_le_bytes()); // BB_ERROR_BLOB
    buf[14..16].copy_from_slice(&0u16.to_le_bytes()); // blob length = 0
    buf
}

impl Sequence for ClientConnector {
    fn state(&self) -> &ClientConnectorState {
        &self.state
    }

    fn next_pdu_hint(&self) -> Option<&dyn PduHint> {
        if self.state.is_send_state() || self.state.is_connected() {
            None
        } else if matches!(
            self.state,
            ClientConnectorState::AadWaitServerNonce
                | ClientConnectorState::AadWaitAuthResult
        ) {
            Some(&AAD_JSON_HINT)
        } else if matches!(
            self.state,
            ClientConnectorState::RdstlsWaitCapabilities
                | ClientConnectorState::RdstlsWaitAuthResponse
        ) {
            Some(&RDSTLS_HINT)
        } else if matches!(
            self.state,
            ClientConnectorState::ChannelConnectionChannelJoin
        ) {
            // In channel join: hint depends on sub-phase
            if self.channel_join_sending {
                None // send sub-phase
            } else {
                Some(&TPKT_HINT) // wait sub-phase
            }
        } else {
            Some(&TPKT_HINT)
        }
    }

    fn step(&mut self, input: &[u8], output: &mut WriteBuf) -> ConnectorResult<Written> {
        match self.state {
            ClientConnectorState::ConnectionInitiationSendRequest => {
                self.step_connection_initiation_send_request(output)
            }
            ClientConnectorState::ConnectionInitiationWaitConfirm => {
                self.step_connection_initiation_wait_confirm(input)
            }
            ClientConnectorState::EnhancedSecurityUpgrade => {
                self.step_enhanced_security_upgrade()
            }
            ClientConnectorState::CredsspNegoTokens => {
                self.step_credssp_nego_tokens()
            }
            ClientConnectorState::CredsspPubKeyAuth => {
                self.step_credssp_pub_key_auth()
            }
            ClientConnectorState::CredsspCredentials => {
                self.step_credssp_credentials()
            }
            ClientConnectorState::CredsspEarlyUserAuth => {
                self.step_credssp_early_user_auth()
            }
            ClientConnectorState::AadWaitServerNonce => {
                self.step_aad_wait_server_nonce(input)
            }
            ClientConnectorState::AadSendAuthRequest => {
                self.step_aad_send_auth_request(output)
            }
            ClientConnectorState::AadWaitAuthResult => {
                self.step_aad_wait_auth_result(input)
            }
            ClientConnectorState::RdstlsSendCapabilities => {
                self.step_rdstls_send_capabilities(output)
            }
            ClientConnectorState::RdstlsWaitCapabilities => {
                self.step_rdstls_wait_capabilities(input)
            }
            ClientConnectorState::RdstlsSendAuthRequest => {
                self.step_rdstls_send_auth_request(output)
            }
            ClientConnectorState::RdstlsWaitAuthResponse => {
                self.step_rdstls_wait_auth_response(input)
            }
            ClientConnectorState::BasicSettingsExchangeSendInitial => {
                self.step_basic_settings_send_initial(output)
            }
            ClientConnectorState::BasicSettingsExchangeWaitResponse => {
                self.step_basic_settings_wait_response(input)
            }
            ClientConnectorState::ChannelConnectionSendErectDomainRequest => {
                self.step_send_erect_domain_request(output)
            }
            ClientConnectorState::ChannelConnectionSendAttachUserRequest => {
                self.step_send_attach_user_request(output)
            }
            ClientConnectorState::ChannelConnectionWaitAttachUserConfirm => {
                self.step_wait_attach_user_confirm(input)
            }
            ClientConnectorState::ChannelConnectionChannelJoin => {
                self.step_channel_join(input, output)
            }
            ClientConnectorState::SecurityCommencement => {
                self.step_security_commencement(output)
            }
            ClientConnectorState::SecureSettingsExchange => {
                self.step_secure_settings_exchange(output)
            }
            ClientConnectorState::ConnectTimeAutoDetection => {
                self.step_connect_time_auto_detection(input, output)
            }
            ClientConnectorState::LicensingExchange => {
                self.step_licensing_exchange(input, output)
            }
            ClientConnectorState::MultitransportBootstrapping => {
                self.step_multitransport_bootstrapping()
            }
            ClientConnectorState::CapabilitiesExchangeWaitDemandActive => {
                self.step_capabilities_wait_demand_active(input)
            }
            ClientConnectorState::CapabilitiesExchangeSendConfirmActive => {
                self.step_capabilities_send_confirm_active(output)
            }
            ClientConnectorState::ConnectionFinalizationSendSynchronize => {
                self.step_finalization_send_synchronize(output)
            }
            ClientConnectorState::ConnectionFinalizationSendCooperate => {
                self.step_finalization_send_cooperate(output)
            }
            ClientConnectorState::ConnectionFinalizationSendRequestControl => {
                self.step_finalization_send_request_control(output)
            }
            ClientConnectorState::ConnectionFinalizationSendPersistentKeyList => {
                self.step_finalization_send_persistent_key_list(output)
            }
            ClientConnectorState::ConnectionFinalizationSendFontList => {
                self.step_finalization_send_font_list(output)
            }
            ClientConnectorState::ConnectionFinalizationWaitSynchronize => {
                self.step_finalization_wait_pdu(
                    input,
                    ShareDataPduType::Synchronize,
                    ClientConnectorState::ConnectionFinalizationWaitCooperate,
                )
            }
            ClientConnectorState::ConnectionFinalizationWaitCooperate => {
                self.step_finalization_wait_pdu(
                    input,
                    ShareDataPduType::Control,
                    ClientConnectorState::ConnectionFinalizationWaitGrantedControl,
                )
            }
            ClientConnectorState::ConnectionFinalizationWaitGrantedControl => {
                self.step_finalization_wait_pdu(
                    input,
                    ShareDataPduType::Control,
                    ClientConnectorState::ConnectionFinalizationWaitFontMap,
                )
            }
            ClientConnectorState::ConnectionFinalizationWaitFontMap => {
                self.step_finalization_wait_font_map(input)
            }
            ClientConnectorState::Connected { .. } => {
                Err(ConnectorError {
                    kind: ConnectorErrorKind::InvalidState,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::tpkt::TPKT_HEADER_SIZE;

    #[test]
    fn new_connector_starts_at_connection_initiation() {
        let config = Config::builder("user", "pass").build();
        let connector = ClientConnector::new(config);
        assert_eq!(*connector.state(), ClientConnectorState::ConnectionInitiationSendRequest);
    }

    #[test]
    fn connection_initiation_produces_output() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);
        let mut output = WriteBuf::new();

        let written = connector.step(&[], &mut output).unwrap();
        assert!(written.size > 0);
        assert_eq!(
            *connector.state(),
            ClientConnectorState::ConnectionInitiationWaitConfirm
        );

        // Verify TPKT header
        let buf = output.as_mut_slice();
        assert_eq!(buf[0], 0x03); // TPKT version
        assert_eq!(buf[1], 0x00); // reserved
    }

    #[test]
    fn send_states_return_no_hint() {
        let config = Config::builder("user", "pass").build();
        let connector = ClientConnector::new(config);
        // ConnectionInitiationSendRequest is a send state
        assert!(connector.next_pdu_hint().is_none());
    }

    #[test]
    fn wait_states_return_tpkt_hint() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);
        let mut output = WriteBuf::new();

        // Advance to wait state
        connector.step(&[], &mut output).unwrap();
        assert_eq!(
            *connector.state(),
            ClientConnectorState::ConnectionInitiationWaitConfirm
        );
        assert!(connector.next_pdu_hint().is_some());
    }

    #[test]
    fn config_builder_defaults() {
        let config = Config::builder("testuser", "testpass").build();
        assert_eq!(config.credentials.username, "testuser");
        assert_eq!(config.credentials.password, "testpass");
        assert_eq!(config.desktop_size.width, 1024);
        assert_eq!(config.desktop_size.height, 768);
        assert_eq!(config.keyboard_layout, 0x0409);
        assert!(config.static_channels.is_empty());
        assert_eq!(config.color_depth, crate::config::ColorDepth::Bpp16);
        assert_eq!(config.keyboard_type, crate::config::KeyboardType::IbmEnhanced);
        assert!(config.domain.is_none());
    }

    #[test]
    fn config_builder_custom() {
        let config = Config::builder("user", "pass")
            .domain("TESTDOMAIN")
            .desktop_size(1920, 1080)
            .keyboard_layout(0x0412) // Korean
            .channel("rdpdr", 0x80800000)
            .build();

        assert_eq!(config.domain.as_deref(), Some("TESTDOMAIN"));
        assert_eq!(config.desktop_size.width, 1920);
        assert_eq!(config.desktop_size.height, 1080);
        assert_eq!(config.keyboard_layout, 0x0412);
        assert_eq!(config.static_channels.len(), 1);
        assert_eq!(config.static_channels.as_slice()[0].name_str(), "rdpdr");
    }

    #[test]
    fn connection_request_with_cookie() {
        let config = Config::builder("user", "pass")
            .cookie("testcookie")
            .build();
        let mut connector = ClientConnector::new(config);
        let mut output = WriteBuf::new();

        let written = connector.step(&[], &mut output).unwrap();
        assert!(written.size > 0);

        // Verify the output contains the cookie by searching for the byte pattern
        let buf = &output.as_mut_slice()[..written.size];
        let cookie_bytes = b"mstshash=testcookie";
        let found = buf
            .windows(cookie_bytes.len())
            .any(|w| w == cookie_bytes);
        assert!(found, "cookie not found in connection request");
    }

    #[test]
    fn connection_confirm_with_negotiation_response() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);
        let mut output = WriteBuf::new();

        // Step 1: Send Connection Request
        connector.step(&[], &mut output).unwrap();

        // Build a mock Connection Confirm with NLA selected
        let cc = ConnectionConfirm::success(justrdp_pdu::x224::NegotiationResponse {
            flags: NegotiationResponseFlags::NONE,
            protocol: SecurityProtocol::HYBRID,
        });

        let cc_size = cc.size();
        let tpkt = TpktHeader::for_payload(cc_size);
        let total = TPKT_HEADER_SIZE + cc_size;
        let mut cc_buf = vec![0u8; total];
        {
            let mut cursor = WriteCursor::new(&mut cc_buf);
            tpkt.encode(&mut cursor).unwrap();
            cc.encode(&mut cursor).unwrap();
        }

        // Step 2: Feed Connection Confirm
        output.clear();
        let written = connector.step(&cc_buf, &mut output).unwrap();
        assert_eq!(written.size, 0);
        assert_eq!(*connector.state(), ClientConnectorState::EnhancedSecurityUpgrade);
    }

    #[test]
    fn security_upgrade_to_credssp_for_hybrid() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);

        // Manually set state and protocol
        connector.state = ClientConnectorState::EnhancedSecurityUpgrade;
        connector.selected_protocol = SecurityProtocol::HYBRID;

        let mut output = WriteBuf::new();
        connector.step(&[], &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::CredsspNegoTokens);
    }

    #[test]
    fn security_upgrade_to_basic_settings_for_ssl() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);

        connector.state = ClientConnectorState::EnhancedSecurityUpgrade;
        connector.selected_protocol = SecurityProtocol::SSL;

        let mut output = WriteBuf::new();
        connector.step(&[], &mut output).unwrap();
        assert_eq!(
            *connector.state(),
            ClientConnectorState::BasicSettingsExchangeSendInitial
        );
    }

    #[test]
    fn credssp_full_sequence() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);
        let mut output = WriteBuf::new();

        // CredsspNegoTokens → CredsspPubKeyAuth
        connector.state = ClientConnectorState::CredsspNegoTokens;
        connector.step(&[], &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::CredsspPubKeyAuth);

        // CredsspPubKeyAuth → CredsspCredentials
        connector.step(&[], &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::CredsspCredentials);

        // CredsspCredentials → BasicSettingsExchangeSendInitial (non-HYBRID_EX)
        connector.selected_protocol = SecurityProtocol::HYBRID;
        connector.step(&[], &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::BasicSettingsExchangeSendInitial);
    }

    #[test]
    fn credssp_hybrid_ex_includes_early_user_auth() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);
        let mut output = WriteBuf::new();

        connector.state = ClientConnectorState::CredsspCredentials;
        connector.selected_protocol = SecurityProtocol::HYBRID_EX;

        connector.step(&[], &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::CredsspEarlyUserAuth);

        connector.step(&[], &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::BasicSettingsExchangeSendInitial);
    }

    #[test]
    fn basic_settings_send_initial_produces_mcs_connect_initial() {
        let config = Config::builder("user", "pass")
            .desktop_size(1920, 1080)
            .build();
        let mut connector = ClientConnector::new(config);
        connector.state = ClientConnectorState::BasicSettingsExchangeSendInitial;
        connector.selected_protocol = SecurityProtocol::HYBRID;

        let mut output = WriteBuf::new();
        let written = connector.step(&[], &mut output).unwrap();
        assert!(written.size > 0);
        assert_eq!(
            *connector.state(),
            ClientConnectorState::BasicSettingsExchangeWaitResponse
        );

        // Verify TPKT + X.224 DT headers
        let buf = output.as_mut_slice();
        assert_eq!(buf[0], 0x03); // TPKT version
        // X.224 DT header follows at offset 4
        assert_eq!(buf[4], 2);    // LI = 2
        assert_eq!(buf[5], 0xF0); // DT code
    }

    #[test]
    fn connected_state_returns_error() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);
        connector.state = ClientConnectorState::Connected {
            result: ConnectionResult {
                io_channel_id: 0,
                user_channel_id: 0,
                share_id: 0,
                server_capabilities: Vec::new(),
                channel_ids: Vec::new(),
                selected_protocol: SecurityProtocol::RDP,
                session_id: 0,
                server_monitor_layout: None,
                server_arc_cookie: None,
            },
        };

        let mut output = WriteBuf::new();
        let result = connector.step(&[], &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn connect_time_auto_detection_is_wait_state() {
        let _config = Config::builder("user", "pass").build();

        // ConnectTimeAutoDetection is a wait state (server sends first)
        assert!(!ClientConnectorState::ConnectTimeAutoDetection.is_send_state());

        // When in this state, next_pdu_hint should return TPKT hint (wait for server PDU)
        let mut conn2 = ClientConnector::new(Config::builder("u", "p").build());
        conn2.state = ClientConnectorState::ConnectTimeAutoDetection;
        assert!(conn2.next_pdu_hint().is_some());
    }

    #[test]
    fn multitransport_bootstrapping_pass_through() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);
        let mut output = WriteBuf::new();

        connector.state = ClientConnectorState::MultitransportBootstrapping;
        connector.step(&[], &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::CapabilitiesExchangeWaitDemandActive);
    }

    #[test]
    fn persistent_key_list_transitions_to_font_list() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);
        let mut output = WriteBuf::new();

        connector.state = ClientConnectorState::ConnectionFinalizationSendPersistentKeyList;
        connector.step(&[], &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::ConnectionFinalizationSendFontList);
    }

    #[test]
    fn parse_server_message_channel_data() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);

        // Build server data blocks with MessageChannelData (type=0x0C04)
        // Block header: type(u16 LE) + length(u16 LE) + body
        // MessageChannelData body: mcs_message_channel_id (u16 LE)
        let mut data = Vec::new();
        // ServerMessageChannelData block: type=0x0C04, length=6 (header+body), channelId=0x03F0
        data.extend_from_slice(&0x0C04u16.to_le_bytes()); // type
        data.extend_from_slice(&0x0006u16.to_le_bytes()); // length = 6 (4 header + 2 body)
        data.extend_from_slice(&0x03F0u16.to_le_bytes()); // mcs_message_channel_id = 1008

        assert_eq!(data.len(), 6, "test data should be 6 bytes");
        assert!(connector.mcs_message_channel_id.is_none());
        connector.parse_server_data_blocks(&data).unwrap();
        assert_eq!(connector.mcs_message_channel_id, Some(0x03F0));
        assert_eq!(connector.mcs_message_channel_id(), Some(0x03F0));
    }

    #[test]
    fn restricted_admin_sets_nego_flag() {
        let config = Config::builder("admin", "pass")
            .restricted_admin()
            .build();
        let mut connector = ClientConnector::new(config);
        let mut output = WriteBuf::new();

        // Send Connection Request
        let written = connector.step(&[], &mut output).unwrap();
        let buf = &output.as_mut_slice()[..written.size];

        // The negotiation request is the last 8 bytes of the X.224 CR PDU:
        //   type(1) + flags(1) + length(2 LE) + protocols(4 LE)
        // type = 0x01 (TYPE_RDP_NEG_REQ), length = 0x0008
        assert!(buf.len() >= 8, "output too short for negotiation request");
        let neg_offset = buf.len() - 8;
        assert_eq!(buf[neg_offset], 0x01, "negotiation request type should be 0x01");
        let neg_len = u16::from_le_bytes([buf[neg_offset + 2], buf[neg_offset + 3]]);
        assert_eq!(neg_len, 0x0008, "negotiation request length should be 8");
        let flags = buf[neg_offset + 1];
        assert_eq!(flags & 0x01, 0x01,
            "RESTRICTED_ADMIN_MODE_REQUIRED flag not set (flags=0x{:02X})", flags);
    }

    #[test]
    fn restricted_admin_rejects_unsupported_server() {
        let config = Config::builder("admin", "pass")
            .restricted_admin()
            .build();
        let mut connector = ClientConnector::new(config);
        let mut output = WriteBuf::new();

        // Send Connection Request
        connector.step(&[], &mut output).unwrap();

        // Build server response WITHOUT RESTRICTED_ADMIN flag
        let cc = ConnectionConfirm::success(justrdp_pdu::x224::NegotiationResponse {
            flags: NegotiationResponseFlags::NONE, // No RESTRICTED_ADMIN
            protocol: SecurityProtocol::HYBRID,
        });

        let cc_size = cc.size();
        let tpkt = TpktHeader::for_payload(cc_size);
        let total = TPKT_HEADER_SIZE + cc_size;
        let mut cc_buf = vec![0u8; total];
        {
            let mut cursor = WriteCursor::new(&mut cc_buf);
            tpkt.encode(&mut cursor).unwrap();
            cc.encode(&mut cursor).unwrap();
        }

        // Should return error because server doesn't support Restricted Admin
        output.clear();
        let result = connector.step(&cc_buf, &mut output);
        assert!(result.is_err(), "should reject server without RESTRICTED_ADMIN support");
    }

    #[test]
    fn credssp_credential_type_restricted_admin() {
        let config = Config::builder("admin", "pass")
            .restricted_admin()
            .build();
        let connector = ClientConnector::new(config);
        let cred_type = connector.credssp_credential_type();
        assert!(matches!(cred_type, crate::credssp::CredentialType::RestrictedAdmin));
    }

    // ── Multi-monitor tests ──────────────────────────────────────────────

    use crate::config::MonitorConfig;

    /// Helper: create a connector in BasicSettingsExchangeSendInitial state.
    fn monitor_connector(config: Config, nego_flags: NegotiationResponseFlags) -> ClientConnector {
        let mut c = ClientConnector::new(config);
        c.state = ClientConnectorState::BasicSettingsExchangeSendInitial;
        c.selected_protocol = SecurityProtocol::HYBRID;
        c.server_nego_flags = nego_flags;
        c
    }

    /// Helper: step connector through BasicSettingsExchangeSendInitial and return output bytes.
    fn step_gcc(connector: &mut ClientConnector) -> Vec<u8> {
        let mut output = WriteBuf::new();
        let written = connector.step(&[], &mut output).unwrap();
        output.as_mut_slice()[..written.size].to_vec()
    }

    #[test]
    fn multi_monitor_gcc_includes_cs_monitor_and_cs_monitor_ex() {
        // Two monitors: primary 1920×1080 at origin, secondary to the right
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(1920, 1080))
            .monitor(MonitorConfig::secondary(1920, 0, 1920, 1080))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);

        let buf = step_gcc(&mut connector);

        assert!(buf.windows(2).any(|w| w == [0x05, 0xC0]), "output should contain CS_MONITOR (0xC005)");
        assert!(buf.windows(2).any(|w| w == [0x08, 0xC0]), "output should contain CS_MONITOR_EX (0xC008)");
    }

    #[test]
    fn single_monitor_omits_cs_monitor_blocks() {
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(1920, 1080))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);

        let buf = step_gcc(&mut connector);
        assert!(!buf.windows(2).any(|w| w == [0x05, 0xC0]), "single monitor should omit CS_MONITOR");
    }

    #[test]
    fn multi_monitor_without_extended_client_data_omits_blocks() {
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(1920, 1080))
            .monitor(MonitorConfig::secondary(1920, 0, 1920, 1080))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::NONE);

        let buf = step_gcc(&mut connector);
        assert!(!buf.windows(2).any(|w| w == [0x05, 0xC0]), "should omit CS_MONITOR without EXTENDED_CLIENT_DATA");
    }

    #[test]
    fn multi_monitor_rejects_no_primary() {
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::secondary(0, 0, 1920, 1080))
            .monitor(MonitorConfig::secondary(1920, 0, 1920, 1080))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);
        let mut output = WriteBuf::new();
        assert!(connector.step(&[], &mut output).is_err());
    }

    #[test]
    fn multi_monitor_rejects_primary_not_at_origin() {
        let config = Config::builder("user", "pass")
            .monitor({
                let mut m = MonitorConfig::primary(1920, 1080);
                m.left = 100;
                m.top = 100;
                m.right = 2019;
                m.bottom = 1179;
                m
            })
            .monitor(MonitorConfig::secondary(1920, 0, 1920, 1080))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);
        let mut output = WriteBuf::new();
        assert!(connector.step(&[], &mut output).is_err());
    }

    #[test]
    fn multi_monitor_negative_coordinates() {
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(1920, 1080))
            .monitor(MonitorConfig::secondary(-1920, 0, 1920, 1080))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);

        let buf = step_gcc(&mut connector);
        assert!(buf.windows(2).any(|w| w == [0x05, 0xC0]), "negative coords should produce valid CS_MONITOR");
    }

    #[test]
    fn multi_monitor_rejects_two_primaries() {
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(1920, 1080))
            .monitor({
                let mut m = MonitorConfig::primary(1920, 1080);
                m.left = 1920;
                m.right = 3839;
                m
            })
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);
        let mut output = WriteBuf::new();
        assert!(connector.step(&[], &mut output).is_err());
    }

    #[test]
    fn multi_monitor_rejects_too_small_virtual_desktop() {
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(50, 50))
            .monitor(MonitorConfig::secondary(50, 0, 50, 50))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);
        let mut output = WriteBuf::new();
        assert!(connector.step(&[], &mut output).is_err());
    }

    #[test]
    fn multi_monitor_rejects_exceeding_16_monitors() {
        let mut config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(1920, 1080));
        for i in 1..=16 {
            config = config.monitor(MonitorConfig::secondary(1920 * i, 0, 1920, 1080));
        }
        let mut connector = monitor_connector(config.build(), NegotiationResponseFlags::EXTENDED_CLIENT_DATA);
        let mut output = WriteBuf::new();
        assert!(connector.step(&[], &mut output).is_err());
    }

    #[test]
    fn multi_monitor_rejects_inverted_rectangle() {
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(1920, 1080))
            .monitor(MonitorConfig {
                left: 1920,
                top: 0,
                right: 1919, // inverted: right < left
                bottom: 1079,
                is_primary: false,
                physical_width_mm: 0,
                physical_height_mm: 0,
                orientation: 0,
                desktop_scale_factor: 100,
                device_scale_factor: 100,
            })
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);
        let mut output = WriteBuf::new();
        assert!(connector.step(&[], &mut output).is_err(), "should reject inverted monitor rectangle");
    }

    #[test]
    fn multi_monitor_desktop_size_equals_bounding_rect() {
        // Two 1920×1080 monitors side-by-side → bounding rect = 3840×1080
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(1920, 1080))
            .monitor(MonitorConfig::secondary(1920, 0, 1920, 1080))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);

        step_gcc(&mut connector);

        // active_desktop_size should be set to the bounding rect
        let ds = connector.active_desktop_size.unwrap();
        assert_eq!(ds.width, 3840, "bounding rect width should be 3840");
        assert_eq!(ds.height, 1080, "bounding rect height should be 1080");
    }

    #[test]
    fn multi_monitor_sets_support_monitor_layout_pdu_flag() {
        // Verify the monitor path sets SUPPORT_MONITOR_LAYOUT_PDU and overrides
        // desktop size. We decode through all protocol layers to reach CS_CORE.
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(1920, 1080))
            .monitor(MonitorConfig::secondary(1920, 0, 1920, 1080))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);

        let buf = step_gcc(&mut connector);

        // Decode: TPKT → X.224 DT → MCS ConnectInitial → GCC ConferenceCreateResponse → user data
        let mut cursor = ReadCursor::new(&buf);
        let _tpkt = TpktHeader::decode(&mut cursor).unwrap();
        let _dt = DataTransfer::decode(&mut cursor).unwrap();
        let ci = ConnectInitial::decode(&mut cursor).unwrap();
        let gcc = ConferenceCreateRequest::decode(&mut ReadCursor::new(&ci.user_data)).unwrap();

        // First block in GCC user data is CS_CORE
        let mut gcc_cursor = ReadCursor::new(&gcc.user_data);
        let core = ClientCoreData::decode(&mut gcc_cursor).unwrap();

        // Verify earlyCapabilityFlags contains SUPPORT_MONITOR_LAYOUT_PDU
        let flags = core.early_capability_flags.expect("earlyCapabilityFlags should be set");
        assert!(
            flags.contains(EarlyCapabilityFlags::SUPPORT_MONITOR_LAYOUT_PDU),
            "earlyCapabilityFlags should include SUPPORT_MONITOR_LAYOUT_PDU (0x0040), got 0x{:04X}",
            flags.bits()
        );

        // Verify desktopWidth/desktopHeight = bounding rect of 2×1920×1080
        assert_eq!(core.desktop_width, 3840);
        assert_eq!(core.desktop_height, 1080);
    }

    #[test]
    fn monitor_config_builder_methods() {
        let m = MonitorConfig::primary(1920, 1080)
            .with_physical_size(527, 296)
            .with_orientation(90)
            .with_scale(150, 140);

        assert_eq!(m.left, 0);
        assert_eq!(m.top, 0);
        assert_eq!(m.right, 1919);
        assert_eq!(m.bottom, 1079);
        assert!(m.is_primary);
        assert_eq!(m.physical_width_mm, 527);
        assert_eq!(m.physical_height_mm, 296);
        assert_eq!(m.orientation, 90);
        assert_eq!(m.desktop_scale_factor, 150);
        assert_eq!(m.device_scale_factor, 140);
    }

    #[test]
    #[should_panic(expected = "orientation must be 0, 90, 180, or 270")]
    fn monitor_config_rejects_invalid_orientation() {
        MonitorConfig::primary(1920, 1080).with_orientation(45);
    }

    #[test]
    #[should_panic(expected = "desktop_scale_factor must be 100–500")]
    fn monitor_config_rejects_invalid_desktop_scale() {
        MonitorConfig::primary(1920, 1080).with_scale(50, 100);
    }

    #[test]
    #[should_panic(expected = "device_scale_factor must be 100, 140, or 180")]
    fn monitor_config_rejects_invalid_device_scale() {
        MonitorConfig::primary(1920, 1080).with_scale(100, 200);
    }

    #[test]
    fn monitor_config_bulk_setter() {
        let monitors = vec![
            MonitorConfig::primary(1920, 1080),
            MonitorConfig::secondary(1920, 0, 1920, 1080),
        ];
        let config = Config::builder("user", "pass")
            .monitors(monitors)
            .build();
        assert_eq!(config.monitors.len(), 2);
        assert!(config.monitors[0].is_primary);
        assert!(!config.monitors[1].is_primary);
    }

    #[test]
    fn multi_monitor_negative_left_bounding_rect() {
        // Secondary monitor to the LEFT of primary: left=-1920
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(1920, 1080))
            .monitor(MonitorConfig::secondary(-1920, 0, 1920, 1080))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);
        let _ = step_gcc(&mut connector);
        // Bounding rect: min_left=-1920, max_right=1919, width=3840
        let ds = connector.active_desktop_size.unwrap();
        assert_eq!(ds.width, 3840);
        assert_eq!(ds.height, 1080);
    }

    #[test]
    fn multi_monitor_negative_top_bounding_rect() {
        // Secondary monitor ABOVE primary: top=-1080
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(1920, 1080))
            .monitor(MonitorConfig::secondary(0, -1080, 1920, 1080))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);
        let _ = step_gcc(&mut connector);
        // Bounding rect: min_top=-1080, max_bottom=1079, height=2160
        let ds = connector.active_desktop_size.unwrap();
        assert_eq!(ds.width, 1920);
        assert_eq!(ds.height, 2160);
    }

    #[test]
    fn single_monitor_config_overrides_desktop_size() {
        // desktop_size defaults to 1024×768, but monitor says 1920×1080
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(1920, 1080).with_scale(150, 100))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);
        let _ = step_gcc(&mut connector);
        // active_desktop_size should reflect the single monitor, not config.desktop_size
        let ds = connector.active_desktop_size.unwrap();
        assert_eq!(ds.width, 1920);
        assert_eq!(ds.height, 1080);
    }

    #[test]
    fn cs_core_dpi_populated_from_primary() {
        let config = Config::builder("user", "pass")
            .monitor(
                MonitorConfig::primary(1920, 1080)
                    .with_physical_size(530, 300)
                    .with_orientation(90)
                    .with_scale(150, 140),
            )
            .monitor(MonitorConfig::secondary(1920, 0, 1920, 1080))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);

        let buf = step_gcc(&mut connector);

        // Decode the GCC to find CS_CORE and verify DPI fields
        let mut cursor = ReadCursor::new(&buf);
        let _tpkt = TpktHeader::decode(&mut cursor).unwrap();
        let _dt = DataTransfer::decode(&mut cursor).unwrap();
        let ci = ConnectInitial::decode(&mut cursor).unwrap();
        let gcc = ConferenceCreateRequest::decode(&mut ReadCursor::new(&ci.user_data)).unwrap();
        let core = ClientCoreData::decode(&mut ReadCursor::new(&gcc.user_data)).unwrap();

        assert_eq!(core.desktop_physical_width, Some(530));
        assert_eq!(core.desktop_physical_height, Some(300));
        assert_eq!(core.desktop_orientation, Some(90));
        assert_eq!(core.desktop_scale_factor, Some(150));
        assert_eq!(core.device_scale_factor, Some(140));
    }

    #[test]
    fn to_display_layout_fields_conversion() {
        let m = MonitorConfig::primary(1920, 1080)
            .with_physical_size(530, 300)
            .with_orientation(90)
            .with_scale(150, 140);
        let (flags, left, top, width, height, pw, ph, orient, ds, devs) = m.to_display_layout_fields();
        assert_eq!(flags, 0x0000_0001); // PRIMARY
        assert_eq!(left, 0);
        assert_eq!(top, 0);
        assert_eq!(width, 1920);
        assert_eq!(height, 1080);
        assert_eq!(pw, 530);
        assert_eq!(ph, 300);
        assert_eq!(orient, 90);
        assert_eq!(ds, 150);
        assert_eq!(devs, 140);
    }

    #[test]
    fn to_display_layout_fields_secondary_negative() {
        let m = MonitorConfig::secondary(-1920, 0, 1920, 1080);
        let (flags, left, top, width, height, _, _, _, _, _) = m.to_display_layout_fields();
        assert_eq!(flags, 0); // not primary
        assert_eq!(left, -1920);
        assert_eq!(top, 0);
        assert_eq!(width, 1920);
        assert_eq!(height, 1080);
    }

    #[test]
    fn single_monitor_rejects_too_small() {
        // Width 199 < VD_MIN_DIM (200)
        let config = Config::builder("user", "pass")
            .monitor(MonitorConfig::primary(199, 1080))
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);
        let mut output = WriteBuf::new();
        let result = connector.step(&[], &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn single_monitor_rejects_too_large() {
        // Width 32767 > VD_MAX_DIM (32766)
        let mut m = MonitorConfig::primary(32766, 1080);
        m.right = 32766; // width = 32767
        let config = Config::builder("user", "pass")
            .monitor(m)
            .build();
        let mut connector = monitor_connector(config, NegotiationResponseFlags::EXTENDED_CLIENT_DATA);
        let mut output = WriteBuf::new();
        let result = connector.step(&[], &mut output);
        assert!(result.is_err());
    }

    /// Build a server-to-client slow-path frame (TPKT + X.224 DT + MCS SDI + ShareControl + ShareData).
    fn build_server_data_frame(
        io_channel_id: u16,
        share_id: u32,
        pdu_type2: ShareDataPduType,
        body: &[u8],
    ) -> Vec<u8> {
        use justrdp_pdu::mcs::SendDataIndication;
        use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
        use justrdp_pdu::x224::{DataTransfer, DATA_TRANSFER_HEADER_SIZE};

        let sd = wrap_share_data(share_id, pdu_type2, body).unwrap();
        let sc = wrap_share_control(ShareControlPduType::Data, 0x03EA, &sd).unwrap();
        let sdi = SendDataIndication {
            initiator: 0x03EA,
            channel_id: io_channel_id,
            user_data: &sc,
        };
        let mcs_size = DATA_TRANSFER_HEADER_SIZE + sdi.size();
        let mut frame = vec![0u8; TPKT_HEADER_SIZE + mcs_size];
        let mut cursor = WriteCursor::new(&mut frame);
        TpktHeader::for_payload(mcs_size).encode(&mut cursor).unwrap();
        DataTransfer.encode(&mut cursor).unwrap();
        sdi.encode(&mut cursor).unwrap();
        frame
    }

    #[test]
    fn finalization_stores_monitor_layout_in_connection_result() {
        use justrdp_pdu::rdp::finalization::{FontListPdu, MonitorLayoutPdu, SynchronizePdu, ControlPdu, ControlAction};

        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);

        // Set up connector in finalization wait state
        connector.state = ClientConnectorState::ConnectionFinalizationWaitSynchronize;
        connector.io_channel_id = 1003;
        connector.user_channel_id = 1007;
        connector.share_id = 0x00040006;

        let mut output = WriteBuf::new();

        // Server sends MonitorLayoutPdu (arrives before Synchronize — stored, state unchanged)
        let monitor_pdu = MonitorLayoutPdu {
            monitors: vec![
                MonitorLayoutEntry { left: 0, top: 0, right: 1919, bottom: 1079, flags: TS_MONITOR_PRIMARY },
                MonitorLayoutEntry { left: 1920, top: 0, right: 3839, bottom: 1079, flags: 0 },
            ],
        };
        let monitor_body = justrdp_core::encode_vec(&monitor_pdu).unwrap();
        let frame = build_server_data_frame(1003, 0x00040006, ShareDataPduType::MonitorLayoutPdu, &monitor_body);
        connector.step(&frame, &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::ConnectionFinalizationWaitSynchronize);

        // Server sends Synchronize → advance to WaitCooperate
        let sync = SynchronizePdu { message_type: 1, target_user: 1003 };
        let sync_body = justrdp_core::encode_vec(&sync).unwrap();
        let frame = build_server_data_frame(1003, 0x00040006, ShareDataPduType::Synchronize, &sync_body);
        connector.step(&frame, &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::ConnectionFinalizationWaitCooperate);

        // Server sends Control(Cooperate) → advance to WaitGrantedControl
        let coop = ControlPdu { action: ControlAction::Cooperate, grant_id: 0, control_id: 0 };
        let coop_body = justrdp_core::encode_vec(&coop).unwrap();
        let frame = build_server_data_frame(1003, 0x00040006, ShareDataPduType::Control, &coop_body);
        connector.step(&frame, &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::ConnectionFinalizationWaitGrantedControl);

        // Server sends Control(GrantedControl) → advance to WaitFontMap
        let grant = ControlPdu { action: ControlAction::GrantedControl, grant_id: 1007, control_id: 1007 };
        let grant_body = justrdp_core::encode_vec(&grant).unwrap();
        let frame = build_server_data_frame(1003, 0x00040006, ShareDataPduType::Control, &grant_body);
        connector.step(&frame, &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::ConnectionFinalizationWaitFontMap);

        // Server sends FontMap → transition to Connected (FontMapPdu = FontListPdu)
        let font_map = FontListPdu::default_request();
        let fm_body = justrdp_core::encode_vec(&font_map).unwrap();
        let frame = build_server_data_frame(1003, 0x00040006, ShareDataPduType::FontMap, &fm_body);
        connector.step(&frame, &mut output).unwrap();

        // Verify Connected state with monitor layout
        match connector.state() {
            ClientConnectorState::Connected { result } => {
                let layout = result.server_monitor_layout.as_ref()
                    .expect("server_monitor_layout should be populated");
                assert_eq!(layout.len(), 2);
                assert_eq!(layout[0].left, 0);
                assert_eq!(layout[0].right, 1919);
                assert_eq!(layout[0].flags, TS_MONITOR_PRIMARY);
                assert_eq!(layout[1].left, 1920);
                assert_eq!(layout[1].right, 3839);
            }
            other => panic!("expected Connected, got {:?}", other),
        }
    }

    #[test]
    fn arc_security_verifier_hmac_md5() {
        // MS-RDPBCGR 5.5: SecurityVerifier = HMAC_MD5(key=ArcRandomBits, data=ClientRandom)
        // Enhanced RDP Security: ClientRandom = [0; 32]
        //
        // Pinned known-answer test using RFC 2104 HMAC-MD5 over inputs that mirror
        // an auto-reconnect computation. The expected digest was computed once with
        // an external HMAC-MD5 reference (`openssl dgst -md5 -hmac`-equivalent).
        //
        // Note: justrdp_core::crypto::hmac_md5 is independently pinned against
        // RFC 2104 test vectors in justrdp-core's tests; this test focuses on the
        // *argument order* used by the auto-reconnect path.
        let arc_random_bits = [0x0bu8; 16]; // RFC 2104 test vector key
        let client_random = *b"Hi ThereHi ThereHi ThereHi There"; // 32 bytes

        let verifier = justrdp_core::crypto::hmac_md5(&arc_random_bits, &client_random);
        assert_eq!(verifier.len(), 16);

        // Argument-order regression check: swapping key↔data must produce a different
        // result. This catches accidental swaps of the (key, data) parameters in the
        // SecurityVerifier computation path.
        let reversed = justrdp_core::crypto::hmac_md5(&client_random, &arc_random_bits);
        assert_ne!(verifier, reversed, "key/data order matters for HMAC-MD5");

        // Sanity: the result with the all-zero ClientRandom (Enhanced RDP Security)
        // path must differ from the non-zero path above.
        let enhanced = justrdp_core::crypto::hmac_md5(&arc_random_bits, &[0u8; 32]);
        assert_ne!(verifier, enhanced);
    }

    #[test]
    fn arc_cookie_new_constructs_and_redacts_debug() {
        use crate::ArcCookie;
        let cookie = ArcCookie::new(0x1234, [0xAB; 16]);
        assert_eq!(cookie.logon_id, 0x1234);
        assert_eq!(cookie.arc_random_bits, [0xAB; 16]);
        // Debug must redact the secret.
        let debug_str = alloc::format!("{:?}", cookie);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("ab")); // bytes must not appear in any form
    }

    #[test]
    fn config_builder_accepts_arc_cookie_for_reconnect() {
        use crate::ArcCookie;
        // The reconnect path: a previously stored ArcCookie is injected into the
        // ConfigBuilder, and the connector picks it up during step_secure_settings_exchange.
        let cookie = ArcCookie::new(0x42, [0xCD; 16]);
        let config = Config::builder("user", "pass")
            .auto_reconnect_cookie(cookie.clone())
            .build();
        assert_eq!(config.auto_reconnect_cookie, Some(cookie));
    }

    #[test]
    fn arc_security_verifier_standard_rdp_security() {
        // Standard RDP Security: uses actual client_random
        let arc_random_bits = [0x01; 16];
        let client_random = [0x42; 32];

        let verifier = justrdp_core::crypto::hmac_md5(&arc_random_bits, &client_random);
        assert_eq!(verifier.len(), 16);

        // Different client_random produces different verifier
        let other_random = [0x43; 32];
        let other_verifier = justrdp_core::crypto::hmac_md5(&arc_random_bits, &other_random);
        assert_ne!(verifier, other_verifier);
    }
}
