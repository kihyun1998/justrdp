#![forbid(unsafe_code)]

//! Client connection state machine implementation.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, PduHint, ReadCursor, WriteBuf, WriteCursor};

use justrdp_pdu::gcc::client::{ClientClusterData, ClientCoreData, ClientNetworkData, ClientSecurityData};
use justrdp_pdu::gcc::server::ServerNetworkData;
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
use justrdp_pdu::rdp::finalization::{ControlAction, ControlPdu, FontListPdu, SynchronizePdu};
use justrdp_pdu::rdp::server_certificate;
use justrdp_pdu::rdp::standard_security::{
    self, FipsSecurityContext, RdpSecurityContext,
    SEC_ENCRYPT, SEC_EXCHANGE_PKT,
    ENCRYPTION_METHOD_FIPS, ENCRYPTION_LEVEL_NONE,
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
        Some((false, pdu_length))
    }
}

static RDSTLS_HINT: RdstlsHint = RdstlsHint;

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
        }
    }

    /// Get the negotiated security protocol.
    pub fn selected_protocol(&self) -> SecurityProtocol {
        self.selected_protocol
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
                // No negotiation response means standard RDP security
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
        if self.selected_protocol.contains(SecurityProtocol::RDSTLS) {
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

    // ── RDSTLS (Remote Credential Guard) ──

    fn step_rdstls_send_capabilities(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        use justrdp_pdu::rdp::rdstls::RdstlsCapabilities;

        let caps = RdstlsCapabilities::new();
        let size = caps.size();
        output.ensure_capacity(size);
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
            crate::config::AuthMode::RestrictedAdmin => {
                // Should not reach here — RestrictedAdmin forces HYBRID protocol,
                // which routes through CredSSP, not RDSTLS.
                return Err(ConnectorError::general(
                    "Restricted Admin does not use RDSTLS (internal routing error)",
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
        output.ensure_capacity(size);
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

    fn step_basic_settings_send_initial(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        // Build GCC client data blocks
        let mut core_data = ClientCoreData::new(self.config.desktop_size.width, self.config.desktop_size.height);
        core_data.keyboard_layout = self.config.keyboard_layout;
        core_data.keyboard_type = self.config.keyboard_type.as_u32();
        core_data.client_name = self.config.client_name.clone();
        core_data.server_selected_protocol = Some(self.selected_protocol.bits());

        let security_data = ClientSecurityData::new();

        let cluster_data = ClientClusterData {
            flags: 0x0000_000D, // REDIRECTION_SUPPORTED | REDIRECTION_VERSION3
            redirected_session_id: 0,
        };

        // Encode client data blocks
        let mut client_data_size = core_data.size() + security_data.size() + cluster_data.size();
        if !self.config.static_channels.is_empty() {
            let net_data = ClientNetworkData {
                channels: self.config.static_channels.as_slice().to_vec(),
            };
            client_data_size += net_data.size();
        }

        let mut client_data = vec![0u8; client_data_size];
        {
            let mut cursor = WriteCursor::new(&mut client_data);
            core_data.encode(&mut cursor)?;
            security_data.encode(&mut cursor)?;
            cluster_data.encode(&mut cursor)?;
            if !self.config.static_channels.is_empty() {
                let net_data = ClientNetworkData {
                    channels: self.config.static_channels.as_slice().to_vec(),
                };
                net_data.encode(&mut cursor)?;
            }
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

        while cursor.len() >= DATA_BLOCK_HEADER_SIZE {
            let block_type = cursor.read_u16_le("ServerDataBlock::type")?;
            let block_length = cursor.read_u16_le("ServerDataBlock::length")? as usize;

            if block_length < DATA_BLOCK_HEADER_SIZE {
                return Err(ConnectorError::general("server data block length too small"));
            }

            let body_length = block_length - DATA_BLOCK_HEADER_SIZE;
            if cursor.len() < body_length {
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
                        let random = block_cursor.read_slice(random_len, "SecData::random")?;
                        let cert_data = block_cursor.read_slice(cert_len, "SecData::cert")?;

                        if random_len == 32 {
                            let mut sr = [0u8; 32];
                            sr.copy_from_slice(random);
                            self.server_random = Some(sr);
                        }

                        // Parse server certificate to extract RSA public key
                        let cert = server_certificate::parse_server_certificate(cert_data)?;
                        self.server_public_key = Some(cert.public_key);
                    }
                }
                t if t == ServerDataBlockType::NetworkData as u16 => {
                    let net = ServerNetworkData::decode(&mut block_cursor)?;
                    self.io_channel_id = net.mcs_channel_id;
                    self.channel_ids = net.channel_ids;
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
            let channel_id = self.channels_to_join[self.join_index];
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
                let _valid = ctx.decrypt(&mut data, &mac);
                Ok((flags, data))
            }
            SecurityMode::Fips(ctx) if flags & SEC_ENCRYPT != 0 => {
                // MS-RDPBCGR TS_SECURITY_HEADER2: padLen(1) then dataSignature(8)
                let pad_len = inner.read_u8("SecurityHeader::padLen")?;
                let mac_bytes = inner.read_slice(8, "SecurityHeader::mac")?;
                let mut mac = [0u8; 8];
                mac.copy_from_slice(mac_bytes);
                let remaining = inner.remaining();
                let encrypted = inner.read_slice(remaining, "SecurityHeader::encryptedData")?;
                let (data, _valid) = ctx.decrypt(encrypted, &mac, pad_len);
                Ok((flags, data))
            }
            _ => {
                // No encryption or SEC_ENCRYPT not set
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

                // FIPS header: flags(2) + flagsHi(2) + padLen(1) + MAC(8) + encrypted_data
                let inner_size = 4 + 1 + 8 + ciphertext.len();
                let mut inner = vec![0u8; inner_size];
                {
                    let mut cursor = WriteCursor::new(&mut inner);
                    cursor.write_u16_le(SEC_ENCRYPT, "SecurityHeader::flags")?;
                    cursor.write_u16_le(0, "SecurityHeader::flagsHi")?;
                    cursor.write_u8(pad_len, "SecurityHeader::padLen")?;
                    cursor.write_slice(&mac, "SecurityHeader::mac")?;
                    cursor.write_slice(&ciphertext, "SecurityHeader::encryptedData")?;
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
        let encrypted_len = encrypted_random.len();
        let inner_size = BASIC_SECURITY_HEADER_SIZE + 4 + encrypted_len;
        let mut inner = vec![0u8; inner_size];
        {
            let mut cursor = WriteCursor::new(&mut inner);
            cursor.write_u16_le(SEC_EXCHANGE_PKT, "SecExchange::flags")?;
            cursor.write_u16_le(0, "SecExchange::flagsHi")?;
            cursor.write_u32_le(encrypted_len as u32, "SecExchange::length")?;
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
        let info = ClientInfoPdu::new(domain_str, &self.config.credentials.username, &self.config.credentials.password)
            .with_performance_flags(self.config.performance_flags);

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
                    let inner_size = 4 + 1 + 8 + ciphertext.len();
                    let mut inner = vec![0u8; inner_size];
                    {
                        let mut cursor = WriteCursor::new(&mut inner);
                        cursor.write_u16_le(sec_flags, "SecurityHeader::flags")?;
                        cursor.write_u16_le(0, "SecurityHeader::flagsHi")?;
                        cursor.write_u8(pad_len, "SecurityHeader::padLen")?;
                        cursor.write_slice(&mac, "SecurityHeader::mac")?;
                        cursor.write_slice(&ciphertext, "SecurityHeader::encryptedData")?;
                    }
                    let size = encode_mcs_send_data(self.user_channel_id, self.io_channel_id, &inner, output)?;
                    self.state = ClientConnectorState::ConnectTimeAutoDetection;
                    Ok(Written::new(size))
                }
                SecurityMode::None => unreachable!(),
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
    /// MS-RDPBCGR 1.3.1.1: server may optionally send auto-detect PDUs.
    /// Currently a pass-through; transitions immediately to licensing.
    fn step_connect_time_auto_detection(&mut self) -> ConnectorResult<Written> {
        self.state = ClientConnectorState::LicensingExchange;
        Ok(Written::nothing())
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
            // Could be a server-side PDU before Demand Active (e.g., Deactivate All)
            // For now, stay in current state
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
            originator_id: self.user_channel_id,
            source_descriptor: vec![0x4D, 0x53, 0x54, 0x53, 0x43, 0x00], // "MSTSC\0"
            capability_sets: self.build_client_capabilities(),
        };

        let confirm_bytes = justrdp_core::encode_vec(&confirm)?;
        let sc_payload = wrap_share_control(
            ShareControlPduType::ConfirmActivePdu,
            self.user_channel_id,
            &confirm_bytes,
        );

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
                extra_flags: 0x040D, // FASTPATH_OUTPUT_SUPPORTED | LONG_CREDENTIALS_SUPPORTED | AUTORECONNECT_SUPPORTED | NO_BITMAP_COMPRESSION_HDR
                update_capability_flag: 0,
                remote_unshare_flag: 0,
                general_compression_level: 0,
                refresh_rect_support: 1,
                suppress_output_support: 1,
            }),
            CapabilitySet::Bitmap(BitmapCapability {
                preferred_bits_per_pixel: self.config.color_depth.as_u16(),
                receive1_bit_per_pixel: 1,
                receive4_bits_per_pixel: 1,
                receive8_bits_per_pixel: 1,
                desktop_width: self.config.desktop_size.width,
                desktop_height: self.config.desktop_size.height,
                pad2a: 0,
                desktop_resize_flag: 1,
                bitmap_compression_flag: 1,
                high_color_flags: 0,
                drawing_flags: 0x08 | 0x10 | 0x20, // DRAW_ALLOW_DYNAMIC_COLOR_FIDELITY | DRAW_ALLOW_COLOR_SUBSAMPLING | DRAW_ALLOW_SKIP_ALPHA
                multiple_rectangle_support: 1,
                pad2b: 0,
            }),
            CapabilitySet::Order(OrderCapability {
                terminal_descriptor: [0u8; 16],
                pad4: 0,
                desktop_save_x_granularity: 1,
                desktop_save_y_granularity: 20,
                pad2a: 0,
                maximum_order_level: 1,
                number_fonts: 0,
                order_flags: 0x0022, // NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT
                order_support: [0u8; 32],
                text_flags: 0,
                order_support_ex_flags: 0,
                pad4b: 0,
                desktop_save_size: 0,
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

    fn step_send_finalization_pdu<T: Encode>(
        &mut self,
        pdu_type2: ShareDataPduType,
        inner: &T,
        next_state: ClientConnectorState,
        output: &mut WriteBuf,
    ) -> ConnectorResult<Written> {
        let inner_bytes = justrdp_core::encode_vec(inner)?;
        let sd_payload = wrap_share_data(self.share_id, pdu_type2, &inner_bytes);
        let sc_payload = wrap_share_control(
            ShareControlPduType::Data,
            self.user_channel_id,
            &sd_payload,
        );
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

    /// Send Persistent Key List PDU (MS-RDPBCGR 2.2.1.17).
    ///
    /// Currently sends an empty persistent key list (no cached bitmaps).
    /// This is a required step in the finalization sequence.
    fn step_finalization_send_persistent_key_list(&mut self, _output: &mut WriteBuf) -> ConnectorResult<Written> {
        // For now, skip persistent key list (no bitmap cache) and go straight to font list.
        // A full implementation would send cached bitmap keys here.
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
            // MS-RDPBCGR 1.3.1.3
            self.state = ClientConnectorState::CapabilitiesExchangeWaitDemandActive;
            return Ok(Written::nothing());
        }

        if sc_hdr.pdu_type != ShareControlPduType::Data {
            // Unknown non-data PDU — stay in same state
            return Ok(Written::nothing());
        }

        let sd_hdr = ShareDataHeader::decode(&mut inner)?;

        if sd_hdr.pdu_type2 != expected_type {
            // Not the expected finalization PDU — stay in same state
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
            self.state = ClientConnectorState::CapabilitiesExchangeWaitDemandActive;
            return Ok(Written::nothing());
        }

        if sc_hdr.pdu_type != ShareControlPduType::Data {
            return Ok(Written::nothing());
        }

        let sd_hdr = ShareDataHeader::decode(&mut inner)?;

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
                self.step_connect_time_auto_detection()
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
            },
        };

        let mut output = WriteBuf::new();
        let result = connector.step(&[], &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn connect_time_auto_detection_pass_through() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);
        let mut output = WriteBuf::new();

        connector.state = ClientConnectorState::ConnectTimeAutoDetection;
        connector.step(&[], &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::LicensingExchange);
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
}
