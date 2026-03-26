#![forbid(unsafe_code)]

//! Client connection state machine implementation.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, PduHint, ReadCursor, WriteBuf, WriteCursor};

use justrdp_pdu::gcc::client::{ClientClusterData, ClientCoreData, ClientNetworkData, ClientSecurityData};
use justrdp_pdu::gcc::server::{ServerCoreData, ServerNetworkData};
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
    self, RdpSecurityContext,
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

    // ── Standard RDP Security state ──
    /// Server random (32 bytes) from ServerSecurityData.
    server_random: Option<[u8; 32]>,
    /// Server encryption method from ServerSecurityData.
    server_encryption_method: u32,
    /// Server encryption level from ServerSecurityData.
    server_encryption_level: u32,
    /// Parsed server RSA public key.
    server_public_key: Option<server_certificate::ServerRsaPublicKey>,
    /// RC4-based security context (active after Security Exchange).
    security_context: Option<RdpSecurityContext>,
}

impl ClientConnector {
    /// Create a new connector with the given configuration.
    pub fn new(config: Config) -> Self {
        Self {
            state: ClientConnectorState::ConnectionInitiation,
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
            server_random: None,
            server_encryption_method: 0,
            server_encryption_level: 0,
            server_public_key: None,
            security_context: None,
        }
    }

    /// Get the negotiated security protocol.
    pub fn selected_protocol(&self) -> SecurityProtocol {
        self.selected_protocol
    }

    /// Get the connection result (only valid after reaching `Connected` state).
    pub fn result(&self) -> Option<ConnectionResult> {
        if self.state != ClientConnectorState::Connected {
            return None;
        }

        let channel_ids = self
            .config
            .channels
            .iter()
            .zip(self.channel_ids.iter())
            .map(|(def, &id)| (String::from(def.name_str()), id))
            .collect();

        Some(ConnectionResult {
            io_channel_id: self.io_channel_id,
            user_channel_id: self.user_channel_id,
            share_id: self.share_id,
            server_capabilities: self.server_capabilities.clone(),
            channel_ids,
            selected_protocol: self.selected_protocol,
        })
    }

    // ── State handlers ──

    fn step_connection_initiation(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let nego = NegotiationRequest::new(self.config.security_protocol);

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

        // Transition based on selected protocol
        if self.selected_protocol != SecurityProtocol::RDP {
            self.state = ClientConnectorState::SecurityUpgrade;
        } else {
            self.state = ClientConnectorState::BasicSettingsExchangeSendInitial;
        }

        Ok(Written::nothing())
    }

    fn step_security_upgrade(&mut self) -> ConnectorResult<Written> {
        // Caller has completed TLS handshake
        if self.selected_protocol.contains(SecurityProtocol::HYBRID)
            || self.selected_protocol.contains(SecurityProtocol::HYBRID_EX)
        {
            self.state = ClientConnectorState::CredSsp;
        } else {
            self.state = ClientConnectorState::BasicSettingsExchangeSendInitial;
        }
        Ok(Written::nothing())
    }

    fn step_credssp(&mut self) -> ConnectorResult<Written> {
        // Caller has completed NLA/CredSSP
        self.state = ClientConnectorState::BasicSettingsExchangeSendInitial;
        Ok(Written::nothing())
    }

    fn step_basic_settings_send_initial(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        // Build GCC client data blocks
        let mut core_data = ClientCoreData::new(self.config.desktop_width, self.config.desktop_height);
        core_data.keyboard_layout = self.config.keyboard_layout;
        core_data.keyboard_type = self.config.keyboard_type;
        core_data.client_name = self.config.client_name.clone();
        core_data.server_selected_protocol = Some(self.selected_protocol.bits());

        let security_data = ClientSecurityData::new();

        let cluster_data = ClientClusterData {
            flags: 0x0000_000D, // REDIRECTION_SUPPORTED | REDIRECTION_VERSION3
            redirected_session_id: 0,
        };

        // Encode client data blocks
        let mut client_data_size = core_data.size() + security_data.size() + cluster_data.size();
        if !self.config.channels.is_empty() {
            let net_data = ClientNetworkData {
                channels: self.config.channels.clone(),
            };
            client_data_size += net_data.size();
        }

        let mut client_data = vec![0u8; client_data_size];
        {
            let mut cursor = WriteCursor::new(&mut client_data);
            core_data.encode(&mut cursor)?;
            security_data.encode(&mut cursor)?;
            cluster_data.encode(&mut cursor)?;
            if !self.config.channels.is_empty() {
                let net_data = ClientNetworkData {
                    channels: self.config.channels.clone(),
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

        self.state = ClientConnectorState::ChannelConnectionSendErectDomain;
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
                    let _core = ServerCoreData::decode(&mut block_cursor)?;
                }
                t if t == ServerDataBlockType::SecurityData as u16 => {
                    // Re-decode from full block (SecurityData decode expects header)
                    // We already stripped the header, so parse fields directly.
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

    fn step_send_erect_domain(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let pdu = ErectDomainRequest {
            sub_height: 0,
            sub_interval: 0,
        };
        let size = encode_slow_path(&pdu, output)?;
        self.state = ClientConnectorState::ChannelConnectionSendAttachUser;
        Ok(Written::new(size))
    }

    fn step_send_attach_user(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let size = encode_slow_path(&AttachUserRequest, output)?;
        self.state = ClientConnectorState::ChannelConnectionWaitAttachConfirm;
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

        self.state = ClientConnectorState::ChannelConnectionSendJoinRequest;
        Ok(Written::nothing())
    }

    fn step_send_join_request(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let channel_id = self.channels_to_join[self.join_index];
        let pdu = ChannelJoinRequest {
            initiator: self.user_channel_id,
            channel_id,
        };
        let size = encode_slow_path(&pdu, output)?;
        self.state = ClientConnectorState::ChannelConnectionWaitJoinConfirm;
        Ok(Written::new(size))
    }

    fn step_wait_join_confirm(&mut self, input: &[u8]) -> ConnectorResult<Written> {
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
            self.state = ClientConnectorState::ChannelConnectionSendJoinRequest;
        } else if self.uses_standard_rdp_security() {
            // Standard RDP Security: send Security Exchange PDU first
            self.state = ClientConnectorState::SecurityExchangeSendClientRandom;
        } else {
            self.state = ClientConnectorState::SecureSettingsExchange;
        }

        Ok(Written::nothing())
    }

    /// Whether this connection uses Standard RDP Security (not TLS/NLA).
    fn uses_standard_rdp_security(&self) -> bool {
        self.selected_protocol == SecurityProtocol::RDP
            && self.server_encryption_method != 0
            && self.server_encryption_level != ENCRYPTION_LEVEL_NONE
    }

    /// Send Security Exchange PDU: encrypted client random.
    ///
    /// MS-RDPBCGR 2.2.1.10: The client generates a 32-byte random, encrypts it
    /// with the server's RSA public key, and sends it in a Security Exchange PDU.
    /// Then derives session keys from (client_random + server_random).
    fn step_security_exchange_send_client_random(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let server_key = self.server_public_key.as_ref()
            .ok_or_else(|| ConnectorError::general("no server public key for security exchange"))?;
        let server_random = self.server_random
            .ok_or_else(|| ConnectorError::general("no server random for security exchange"))?;

        // Generate 32-byte client random
        // For now, use a deterministic placeholder — the caller should inject randomness.
        // TODO: Accept random source from caller (via Config or trait).
        let client_random: [u8; 32] = {
            // Simple PRNG seeded from server random (NOT cryptographically secure).
            // Real implementation should use OS randomness.
            let mut cr = [0u8; 32];
            let seed = &server_random;
            for i in 0..32 {
                cr[i] = seed[i] ^ (i as u8).wrapping_mul(0x5A).wrapping_add(0x36);
            }
            cr
        };

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

        // Derive session keys
        if self.server_encryption_method == ENCRYPTION_METHOD_FIPS {
            // FIPS mode: use 3DES + SHA-1
            // TODO: Wire up FipsSecurityContext when FIPS flow is fully tested
            return Err(ConnectorError::general("FIPS Standard RDP Security not yet fully wired"));
        }

        let keys = standard_security::derive_session_keys(
            &client_random,
            &server_random,
            self.server_encryption_method,
        );

        // Determine if salted MAC should be used
        // SEC_SECURE_CHECKSUM is used when the server supports it (RDP 5.2+)
        let use_salted_mac = true; // Modern servers support this

        self.security_context = Some(RdpSecurityContext::new(keys, use_salted_mac));
        self.state = ClientConnectorState::SecureSettingsExchange;

        Ok(Written::new(size))
    }

    fn step_secure_settings_exchange(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let info = ClientInfoPdu::new(&self.config.domain, &self.config.username, &self.config.password);

        if let Some(ref mut sec_ctx) = self.security_context {
            // Standard RDP Security: encrypt the Client Info PDU
            let info_size = info.size();
            let mut info_bytes = vec![0u8; info_size];
            {
                let mut cursor = WriteCursor::new(&mut info_bytes);
                info.encode(&mut cursor)?;
            }

            // Encrypt and get MAC
            let mac = sec_ctx.encrypt(&mut info_bytes);

            // Build: flags(2) + flagsHi(2) + MAC(8) + encrypted_data
            let inner_size = BASIC_SECURITY_HEADER_SIZE + 8 + info_bytes.len();
            let mut inner = vec![0u8; inner_size];
            {
                let mut cursor = WriteCursor::new(&mut inner);
                cursor.write_u16_le(SEC_INFO_PKT | SEC_ENCRYPT, "SecurityHeader::flags")?;
                cursor.write_u16_le(0, "SecurityHeader::flagsHi")?;
                cursor.write_slice(&mac, "SecurityHeader::mac")?;
                cursor.write_slice(&info_bytes, "SecurityHeader::encryptedData")?;
            }

            let size = encode_mcs_send_data(self.user_channel_id, self.io_channel_id, &inner, output)?;
            self.state = ClientConnectorState::LicensingWait;
            Ok(Written::new(size))
        } else {
            // TLS/NLA mode: send unencrypted (basic security header only)
            let info_size = info.size();
            let inner_size = BASIC_SECURITY_HEADER_SIZE + info_size;
            let mut inner = vec![0u8; inner_size];
            {
                let mut cursor = WriteCursor::new(&mut inner);
                cursor.write_u16_le(SEC_INFO_PKT, "SecurityHeader::flags")?;
                cursor.write_u16_le(0, "SecurityHeader::flagsHi")?;
                info.encode(&mut cursor)?;
            }

            let size = encode_mcs_send_data(self.user_channel_id, self.io_channel_id, &inner, output)?;
            self.state = ClientConnectorState::LicensingWait;
            Ok(Written::new(size))
        }
    }

    fn step_licensing_wait(&mut self, input: &[u8]) -> ConnectorResult<Written> {
        let mut cursor = ReadCursor::new(input);
        let _tpkt = TpktHeader::decode(&mut cursor)?;
        let _dt = DataTransfer::decode(&mut cursor)?;

        // Decode MCS SendDataIndication
        let sdi = SendDataIndication::decode(&mut cursor)?;
        let mut inner = ReadCursor::new(sdi.user_data);

        // Read security header
        let flags = inner.read_u16_le("SecurityHeader::flags")?;
        let _flags_hi = inner.read_u16_le("SecurityHeader::flagsHi")?;

        if flags & SEC_LICENSE_PKT == 0 {
            // Not a licensing PDU — could be auto-detect or something else.
            // Stay in current state and wait for licensing PDU.
            return Ok(Written::nothing());
        }

        // Decode license preamble
        let preamble = LicensePreamble::decode(&mut inner)?;

        match preamble.msg_type {
            LicenseMsgType::ErrorAlert => {
                // Decode the error message
                // We need to re-parse from after the security header, with the preamble included
                // But we already consumed the preamble, so decode the rest
                let error_code_val = inner.read_u32_le("LicenseError::errorCode")?;
                let error_code = justrdp_pdu::rdp::licensing::LicenseErrorCode::from_u32(error_code_val)?;
                let _state_transition = inner.read_u32_le("LicenseError::stateTransition")?;

                if error_code == LicenseErrorCode::StatusValidClient {
                    // Licensing complete
                    self.state = ClientConnectorState::CapabilitiesWaitDemandActive;
                    Ok(Written::nothing())
                } else {
                    Err(ConnectorError {
                        kind: ConnectorErrorKind::LicensingError(error_code),
                    })
                }
            }
            _ => {
                // Full licensing negotiation not supported yet
                Err(ConnectorError::general("full licensing negotiation not supported"))
            }
        }
    }

    fn step_capabilities_wait_demand_active(&mut self, input: &[u8]) -> ConnectorResult<Written> {
        let mut cursor = ReadCursor::new(input);
        let _tpkt = TpktHeader::decode(&mut cursor)?;
        let _dt = DataTransfer::decode(&mut cursor)?;

        let sdi = SendDataIndication::decode(&mut cursor)?;
        let mut inner = ReadCursor::new(sdi.user_data);

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
        self.server_capabilities = demand.capability_sets;

        self.state = ClientConnectorState::CapabilitiesSendConfirmActive;
        Ok(Written::nothing())
    }

    fn step_capabilities_send_confirm_active(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let confirm = ConfirmActivePdu {
            share_id: self.share_id,
            originator_id: 0x03EA, // user channel ID + 1001 convention
            source_descriptor: vec![0x4D, 0x53, 0x54, 0x53, 0x43, 0x00], // "MSTSC\0"
            capability_sets: self.build_client_capabilities(),
        };

        let confirm_bytes = justrdp_core::encode_vec(&confirm)?;
        let sc_payload = wrap_share_control(
            ShareControlPduType::ConfirmActivePdu,
            self.user_channel_id,
            &confirm_bytes,
        );

        let size = encode_mcs_send_data(self.user_channel_id, self.io_channel_id, &sc_payload, output)?;
        self.state = ClientConnectorState::FinalizationSendSynchronize;
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
                preferred_bits_per_pixel: 16,
                receive1_bit_per_pixel: 1,
                receive4_bits_per_pixel: 1,
                receive8_bits_per_pixel: 1,
                desktop_width: self.config.desktop_width,
                desktop_height: self.config.desktop_height,
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
                keyboard_type: self.config.keyboard_type,
                keyboard_sub_type: 0,
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
        let size = encode_mcs_send_data(self.user_channel_id, self.io_channel_id, &sc_payload, output)?;
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
            ClientConnectorState::FinalizationSendCooperate,
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
            ClientConnectorState::FinalizationSendRequestControl,
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
            ClientConnectorState::FinalizationSendFontList,
            output,
        )
    }

    fn step_finalization_send_font_list(&mut self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let pdu = FontListPdu::default_request();
        self.step_send_finalization_pdu(
            ShareDataPduType::FontList,
            &pdu,
            ClientConnectorState::FinalizationWaitSynchronize,
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
        let mut inner = ReadCursor::new(sdi.user_data);

        let sc_hdr = ShareControlHeader::decode(&mut inner)?;

        if sc_hdr.pdu_type != ShareControlPduType::Data {
            // Not a data PDU — could be Deactivate All, etc.
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
}

impl Sequence for ClientConnector {
    fn state(&self) -> &ClientConnectorState {
        &self.state
    }

    fn next_pdu_hint(&self) -> Option<&dyn PduHint> {
        if self.state.is_send_state() || self.state == ClientConnectorState::Connected {
            None
        } else {
            Some(&TPKT_HINT)
        }
    }

    fn step(&mut self, input: &[u8], output: &mut WriteBuf) -> ConnectorResult<Written> {
        match self.state {
            ClientConnectorState::ConnectionInitiation => {
                self.step_connection_initiation(output)
            }
            ClientConnectorState::ConnectionInitiationWaitConfirm => {
                self.step_connection_initiation_wait_confirm(input)
            }
            ClientConnectorState::SecurityUpgrade => {
                self.step_security_upgrade()
            }
            ClientConnectorState::CredSsp => {
                self.step_credssp()
            }
            ClientConnectorState::BasicSettingsExchangeSendInitial => {
                self.step_basic_settings_send_initial(output)
            }
            ClientConnectorState::BasicSettingsExchangeWaitResponse => {
                self.step_basic_settings_wait_response(input)
            }
            ClientConnectorState::ChannelConnectionSendErectDomain => {
                self.step_send_erect_domain(output)
            }
            ClientConnectorState::ChannelConnectionSendAttachUser => {
                self.step_send_attach_user(output)
            }
            ClientConnectorState::ChannelConnectionWaitAttachConfirm => {
                self.step_wait_attach_user_confirm(input)
            }
            ClientConnectorState::ChannelConnectionSendJoinRequest => {
                self.step_send_join_request(output)
            }
            ClientConnectorState::ChannelConnectionWaitJoinConfirm => {
                self.step_wait_join_confirm(input)
            }
            ClientConnectorState::SecurityExchangeSendClientRandom => {
                self.step_security_exchange_send_client_random(output)
            }
            ClientConnectorState::SecureSettingsExchange => {
                self.step_secure_settings_exchange(output)
            }
            ClientConnectorState::LicensingWait => {
                self.step_licensing_wait(input)
            }
            ClientConnectorState::CapabilitiesWaitDemandActive => {
                self.step_capabilities_wait_demand_active(input)
            }
            ClientConnectorState::CapabilitiesSendConfirmActive => {
                self.step_capabilities_send_confirm_active(output)
            }
            ClientConnectorState::FinalizationSendSynchronize => {
                self.step_finalization_send_synchronize(output)
            }
            ClientConnectorState::FinalizationSendCooperate => {
                self.step_finalization_send_cooperate(output)
            }
            ClientConnectorState::FinalizationSendRequestControl => {
                self.step_finalization_send_request_control(output)
            }
            ClientConnectorState::FinalizationSendFontList => {
                self.step_finalization_send_font_list(output)
            }
            ClientConnectorState::FinalizationWaitSynchronize => {
                self.step_finalization_wait_pdu(
                    input,
                    ShareDataPduType::Synchronize,
                    ClientConnectorState::FinalizationWaitCooperate,
                )
            }
            ClientConnectorState::FinalizationWaitCooperate => {
                self.step_finalization_wait_pdu(
                    input,
                    ShareDataPduType::Control,
                    ClientConnectorState::FinalizationWaitGrantedControl,
                )
            }
            ClientConnectorState::FinalizationWaitGrantedControl => {
                self.step_finalization_wait_pdu(
                    input,
                    ShareDataPduType::Control,
                    ClientConnectorState::FinalizationWaitFontMap,
                )
            }
            ClientConnectorState::FinalizationWaitFontMap => {
                self.step_finalization_wait_pdu(
                    input,
                    ShareDataPduType::FontMap,
                    ClientConnectorState::Connected,
                )
            }
            ClientConnectorState::Connected => {
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
        assert_eq!(*connector.state(), ClientConnectorState::ConnectionInitiation);
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
        // ConnectionInitiation is a send state
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
        assert_eq!(config.username, "testuser");
        assert_eq!(config.password, "testpass");
        assert_eq!(config.desktop_width, 1024);
        assert_eq!(config.desktop_height, 768);
        assert_eq!(config.keyboard_layout, 0x0409);
        assert!(config.channels.is_empty());
    }

    #[test]
    fn config_builder_custom() {
        let config = Config::builder("user", "pass")
            .domain("TESTDOMAIN")
            .desktop_size(1920, 1080)
            .keyboard_layout(0x0412) // Korean
            .channel("rdpdr", 0x80800000)
            .build();

        assert_eq!(config.domain, "TESTDOMAIN");
        assert_eq!(config.desktop_width, 1920);
        assert_eq!(config.desktop_height, 1080);
        assert_eq!(config.keyboard_layout, 0x0412);
        assert_eq!(config.channels.len(), 1);
        assert_eq!(config.channels[0].name_str(), "rdpdr");
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
        assert_eq!(*connector.state(), ClientConnectorState::SecurityUpgrade);
    }

    #[test]
    fn security_upgrade_to_credssp_for_hybrid() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);

        // Manually set state and protocol
        connector.state = ClientConnectorState::SecurityUpgrade;
        connector.selected_protocol = SecurityProtocol::HYBRID;

        let mut output = WriteBuf::new();
        connector.step(&[], &mut output).unwrap();
        assert_eq!(*connector.state(), ClientConnectorState::CredSsp);
    }

    #[test]
    fn security_upgrade_to_basic_settings_for_ssl() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);

        connector.state = ClientConnectorState::SecurityUpgrade;
        connector.selected_protocol = SecurityProtocol::SSL;

        let mut output = WriteBuf::new();
        connector.step(&[], &mut output).unwrap();
        assert_eq!(
            *connector.state(),
            ClientConnectorState::BasicSettingsExchangeSendInitial
        );
    }

    #[test]
    fn credssp_to_basic_settings() {
        let config = Config::builder("user", "pass").build();
        let mut connector = ClientConnector::new(config);

        connector.state = ClientConnectorState::CredSsp;

        let mut output = WriteBuf::new();
        connector.step(&[], &mut output).unwrap();
        assert_eq!(
            *connector.state(),
            ClientConnectorState::BasicSettingsExchangeSendInitial
        );
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
        connector.state = ClientConnectorState::Connected;

        let mut output = WriteBuf::new();
        let result = connector.step(&[], &mut output);
        assert!(result.is_err());
    }
}
