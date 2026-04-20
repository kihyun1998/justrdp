#![forbid(unsafe_code)]

//! Server acceptor state machine implementation.

use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, PduHint, ReadCursor, WriteBuf, WriteCursor};

use justrdp_pdu::mcs::{
    AttachUserConfirm, AttachUserRequest, ChannelJoinConfirm, ChannelJoinRequest, ConnectInitial,
    ConnectResponse, ConnectResponseResult, DomainParameters, ErectDomainRequest,
};
use justrdp_pdu::tpkt::{TpktHeader, TpktHint, TPKT_HEADER_SIZE};
use justrdp_pdu::x224::{
    ConnectionConfirm, ConnectionRequest, ConnectionRequestData, DataTransfer, NegotiationFailure,
    NegotiationFailureCode, NegotiationRequestFlags, NegotiationResponse,
    NegotiationResponseFlags, SecurityProtocol, DATA_TRANSFER_HEADER_SIZE,
};

use crate::config::AcceptorConfig;
use crate::encode_helpers::encode_connection_confirm;
use crate::error::{AcceptorError, AcceptorErrorKind, AcceptorResult};
use crate::mcs::{
    allocate_channel_ids, build_server_data_blocks, decode_connect_initial_gcc,
    wrap_server_gcc, ChannelAllocation, ClientGccData, ServerGccInputs,
};
use crate::result::{AcceptanceResult, ClientRequestInfo, Written};
use crate::sequence::Sequence;
use crate::state::ServerAcceptorState;

/// TPKT hint for PDU boundary detection.
static TPKT_HINT: TpktHint = TpktHint;

/// RDP server connection acceptance state machine.
///
/// Drives the full RDP server connection sequence (MS-RDPBCGR 1.3.1.1) from
/// the server side, without performing any I/O. The caller reads/writes
/// network bytes and feeds them to `step()`.
pub struct ServerAcceptor {
    state: ServerAcceptorState,
    config: AcceptorConfig,

    /// Information captured from the client's CR. Populated in
    /// `WaitConnectionRequest` and consumed when sending the CC.
    client_request: Option<ClientRequestInfo>,
    /// Pending Connection Confirm computed by `WaitConnectionRequest`.
    /// Encoded and consumed by `SendConnectionConfirm`.
    pending_confirm: Option<ConnectionConfirm>,
    /// Whether the pending CC carries a `RDP_NEG_FAILURE`. Used to drive
    /// the post-send transition into `NegotiationFailed` (terminal).
    pending_is_failure: bool,

    // ── Negotiated values (filled across phases) ──
    selected_protocol: SecurityProtocol,
    server_nego_flags: NegotiationResponseFlags,

    // ── Phase 4: MCS state ──
    /// Captured client GCC data from the MCS Connect Initial.
    client_gcc: Option<ClientGccData>,
    /// Channel allocation produced from the client's CS_NET request.
    channel_alloc: Option<ChannelAllocation>,
    /// Pre-built MCS Connect Response wire bytes (TPKT + X.224 DT + BER
    /// ConnectResponse). Computed in `WaitMcsConnectInitial`, drained in
    /// `SendMcsConnectResponse`.
    pending_connect_response: Option<Vec<u8>>,

    // ── Phase 5: Channel Connection state ──
    /// Sub-phase within `ChannelConnection`. Tracks the
    /// Erect Domain → Attach User → Channel Join handshake without
    /// adding a separate `ServerAcceptorState` variant per step.
    channel_phase: ChannelPhase,
    /// MCS user channel ID assigned to the client. Filled when the
    /// AttachUserRequest is received; sent back in AttachUserConfirm.
    user_channel_id: u16,
    /// Channels the client must join (in order):
    ///   user channel, I/O channel, optional message channel, then
    ///   each static virtual channel.
    channels_to_join: Vec<u16>,
    /// Index into `channels_to_join` for the next ChannelJoinConfirm.
    channel_join_index: usize,
    /// Channel ID captured from the most recent ChannelJoinRequest;
    /// echoed back in the corresponding ChannelJoinConfirm.
    pending_join_requested: Option<u16>,
}

/// Sub-phase within the `ChannelConnection` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelPhase {
    /// Waiting for the client's MCS Erect Domain Request (no response).
    WaitErectDomainRequest,
    /// Waiting for the client's MCS Attach User Request.
    WaitAttachUserRequest,
    /// Pending MCS Attach User Confirm to send back.
    SendAttachUserConfirm,
    /// Waiting for the next MCS Channel Join Request.
    WaitChannelJoinRequest,
    /// Pending MCS Channel Join Confirm to send back.
    SendChannelJoinConfirm,
    /// All channels joined; the next `step()` transitions out of
    /// `ChannelConnection` into the next phase.
    Done,
}

impl ServerAcceptor {
    /// Create a new acceptor.
    pub fn new(config: AcceptorConfig) -> Self {
        Self {
            state: ServerAcceptorState::WaitConnectionRequest,
            config,
            client_request: None,
            pending_confirm: None,
            pending_is_failure: false,
            selected_protocol: SecurityProtocol::RDP,
            server_nego_flags: NegotiationResponseFlags::NONE,
            client_gcc: None,
            channel_alloc: None,
            pending_connect_response: None,
            channel_phase: ChannelPhase::WaitErectDomainRequest,
            user_channel_id: 0,
            channels_to_join: Vec::new(),
            channel_join_index: 0,
            pending_join_requested: None,
        }
    }

    /// MCS user channel ID assigned to the joined user. Available once
    /// the acceptor has processed the AttachUserRequest.
    pub fn user_channel_id(&self) -> u16 {
        self.user_channel_id
    }

    /// Captured client GCC data from the MCS Connect Initial. Available
    /// once the acceptor has advanced past `WaitMcsConnectInitial`.
    pub fn client_gcc(&self) -> Option<&ClientGccData> {
        self.client_gcc.as_ref()
    }

    /// MCS channel allocation. Available once the acceptor has advanced
    /// past `WaitMcsConnectInitial`.
    pub fn channel_allocation(&self) -> Option<&ChannelAllocation> {
        self.channel_alloc.as_ref()
    }

    /// Returns the active configuration.
    pub fn config(&self) -> &AcceptorConfig {
        &self.config
    }

    /// Returns information captured from the client's Connection Request, if
    /// any has been seen yet.
    pub fn client_request(&self) -> Option<&ClientRequestInfo> {
        self.client_request.as_ref()
    }

    /// Returns the security protocol the server selected, or
    /// `SecurityProtocol::RDP` (0) before negotiation completes.
    pub fn selected_protocol(&self) -> SecurityProtocol {
        self.selected_protocol
    }

    // ── State handlers ──

    fn step_wait_connection_request(&mut self, input: &[u8]) -> AcceptorResult<Written> {
        // Decode TPKT then X.224 CR.
        let mut cursor = ReadCursor::new(input);
        let _tpkt = TpktHeader::decode(&mut cursor)?;
        let cr = ConnectionRequest::decode(&mut cursor)?;

        // Capture cookie / routing token.
        let (cookie, routing_token) = match cr.data {
            Some(ConnectionRequestData::Cookie(c)) => (Some(c), None),
            Some(ConnectionRequestData::RoutingToken(t)) => (None, Some(t)),
            None => (None, None),
        };

        // Extract requested protocols and flags. When `RDP_NEG_REQ` is
        // absent the client is a legacy RDP 4.x/5.0 station -- treat it as
        // requesting `PROTOCOL_RDP` (0) only and remember it had no nego
        // request so the CC is sent without `rdpNegData`.
        let (requested_protocols, request_flags, had_nego) = match cr.negotiation {
            Some(nego) => (nego.protocols, nego.flags, true),
            None => (
                SecurityProtocol::RDP,
                NegotiationRequestFlags::NONE,
                false,
            ),
        };

        let info = ClientRequestInfo {
            cookie,
            routing_token,
            requested_protocols,
            request_flags,
            had_negotiation_request: had_nego,
        };

        // Run protocol selection, build the pending CC.
        let (cc, is_failure, selected, response_flags) = self.build_response(&info);

        self.client_request = Some(info);
        self.pending_confirm = Some(cc);
        self.pending_is_failure = is_failure;
        self.selected_protocol = selected;
        self.server_nego_flags = response_flags;
        self.state = ServerAcceptorState::SendConnectionConfirm;
        Ok(Written::nothing())
    }

    fn step_send_connection_confirm(&mut self, output: &mut WriteBuf) -> AcceptorResult<Written> {
        let cc = self
            .pending_confirm
            .take()
            .ok_or_else(|| AcceptorError::general("no pending Connection Confirm"))?;
        let size = encode_connection_confirm(&cc, output)?;

        if self.pending_is_failure {
            // Remember the failure code so the caller can attribute the
            // disconnect even though the wire bytes are already buffered.
            let code = match cc.negotiation {
                Some(justrdp_pdu::x224::ConnectionConfirmNegotiation::Failure(f)) => Some(f.code),
                _ => None,
            };
            self.state = ServerAcceptorState::NegotiationFailed;
            if let Some(code) = code {
                return Err(AcceptorError {
                    kind: AcceptorErrorKind::NegotiationFailed(code),
                });
            }
            return Err(AcceptorError::general(
                "negotiation failed without a failure code",
            ));
        }

        // Branch on the selected protocol. Standard RDP Security goes
        // straight to MCS; everything else funnels through TLS.
        if self.selected_protocol == SecurityProtocol::RDP {
            self.state = ServerAcceptorState::WaitMcsConnectInitial;
        } else {
            self.state = ServerAcceptorState::TlsAccept;
        }
        Ok(Written::new(size))
    }

    /// Compute the Connection Confirm to send back, based on the captured
    /// client request. Returns `(cc, is_failure, selected_protocol,
    /// response_flags)`.
    ///
    /// MS-RDPBCGR 2.2.1.2.1 / 2.2.1.2.2.
    fn build_response(
        &self,
        info: &ClientRequestInfo,
    ) -> (
        ConnectionConfirm,
        bool,
        SecurityProtocol,
        NegotiationResponseFlags,
    ) {
        // Special legacy path: no `RDP_NEG_REQ` in CR. The client expects
        // a CC with no `rdpNegData` and Standard RDP Security thereafter.
        // If the server refuses Standard RDP Security in this case there
        // is no failure code that a legacy client can interpret -- the
        // caller must close the connection after this CC. We still emit
        // an empty CC so the wire transcript is well-formed.
        if !info.had_negotiation_request {
            if !self.config.supports_protocol(SecurityProtocol::RDP)
                || self.config.require_enhanced_security
            {
                // Legacy client cannot parse `RDP_NEG_FAILURE`, so just
                // send the legacy CC. Mark as failure so the caller tears
                // the connection down. Keep `selected_protocol = RDP` for
                // diagnostic purposes.
                return (
                    ConnectionConfirm::legacy(),
                    true,
                    SecurityProtocol::RDP,
                    NegotiationResponseFlags::NONE,
                );
            }
            return (
                ConnectionConfirm::legacy(),
                false,
                SecurityProtocol::RDP,
                NegotiationResponseFlags::NONE,
            );
        }

        // Modern path: pick a protocol from the intersection.
        match self.select_protocol(info.requested_protocols) {
            Ok(selected) => {
                // Enhanced-security selection requires a TLS certificate
                // for everything except Standard RDP Security.
                if selected != SecurityProtocol::RDP && !self.config.tls_certificate_available {
                    let failure = NegotiationFailure {
                        code: NegotiationFailureCode::SslCertNotOnServer,
                    };
                    return (
                        ConnectionConfirm::failure(failure),
                        true,
                        SecurityProtocol::RDP,
                        NegotiationResponseFlags::NONE,
                    );
                }

                let flags = self.build_response_flags(info.request_flags);
                let response = NegotiationResponse {
                    flags,
                    protocol: selected,
                };
                (
                    ConnectionConfirm::success(response),
                    false,
                    selected,
                    flags,
                )
            }
            Err(code) => {
                let failure = NegotiationFailure { code };
                (
                    ConnectionConfirm::failure(failure),
                    true,
                    SecurityProtocol::RDP,
                    NegotiationResponseFlags::NONE,
                )
            }
        }
    }

    /// Pick the highest-priority protocol that both client and server
    /// support, or the failure code to emit when no intersection exists.
    ///
    /// Priority order matches Windows Server behaviour (and is the order
    /// most clients expect): HYBRID_EX > HYBRID > RDSAAD > RDSTLS > SSL >
    /// RDP. The MS-RDPBCGR spec leaves this ordering unspecified.
    fn select_protocol(
        &self,
        client_requested: SecurityProtocol,
    ) -> Result<SecurityProtocol, NegotiationFailureCode> {
        let server = self.config.supported_protocols;

        // Priority 1: HYBRID_EX (CredSSP + Early User Auth).
        if client_requested.contains(SecurityProtocol::HYBRID_EX)
            && server.contains(SecurityProtocol::HYBRID_EX)
        {
            return Ok(SecurityProtocol::HYBRID_EX);
        }
        // Priority 2: HYBRID (CredSSP).
        if client_requested.contains(SecurityProtocol::HYBRID)
            && server.contains(SecurityProtocol::HYBRID)
        {
            return Ok(SecurityProtocol::HYBRID);
        }
        // Priority 3: RDSAAD (Azure AD, opt-in).
        if client_requested.contains(SecurityProtocol::AAD)
            && server.contains(SecurityProtocol::AAD)
        {
            return Ok(SecurityProtocol::AAD);
        }
        // Priority 4: RDSTLS (Remote Credential Guard token mode).
        if client_requested.contains(SecurityProtocol::RDSTLS)
            && server.contains(SecurityProtocol::RDSTLS)
        {
            return Ok(SecurityProtocol::RDSTLS);
        }
        // Priority 5: SSL (TLS only).
        if client_requested.contains(SecurityProtocol::SSL)
            && server.contains(SecurityProtocol::SSL)
        {
            return Ok(SecurityProtocol::SSL);
        }
        // Priority 6: PROTOCOL_RDP (Standard RDP Security).
        // PROTOCOL_RDP is not a flag bit; it's the *absence* of all
        // enhanced protocols. So we ask "did the client request any
        // enhanced protocols at all?" by checking whether
        // `requested_protocols.bits() == 0`. Both sides must allow it.
        if client_requested.bits() == 0
            && self.config.supports_protocol(SecurityProtocol::RDP)
            && !self.config.require_enhanced_security
        {
            return Ok(SecurityProtocol::RDP);
        }

        // No common protocol -- pick the most accurate failure code.
        // Cases (MS-RDPBCGR 2.2.1.2.2):
        //  * Server requires enhanced security but client only requested
        //    `PROTOCOL_RDP`  -> SSL_REQUIRED_BY_SERVER (0x01)
        //  * Server only supports `PROTOCOL_RDP` but client requested
        //    enhanced        -> SSL_NOT_ALLOWED_BY_SERVER (0x02)
        //  * Server requires CredSSP but client only requested SSL/RDSTLS
        //                    -> HYBRID_REQUIRED_BY_SERVER (0x05)
        //  * Server requires AAD but client did not advertise it
        //                    -> ENTRA_AUTH_REQUIRED_BY_SERVER (0x07)
        //
        // The spec does not enumerate every (server_supported,
        // client_requested) combination. For combinations that fall
        // outside the explicit cases above we emit the code whose textual
        // meaning is closest to the actual mismatch.
        //
        // PROTOCOL_RDP is encoded as the absence of all enhanced bits,
        // so "server has enhanced bits" and "client requested PROTOCOL_RDP
        // only" are checked via raw bit tests rather than `contains()`
        // (which would always succeed for a zero argument).
        let server_has_enhanced = server.bits() != 0;
        let client_only_rdp = client_requested.bits() == 0;
        let server_only_rdp = !server_has_enhanced;
        let server_has_cred = server.contains(SecurityProtocol::HYBRID)
            || server.contains(SecurityProtocol::HYBRID_EX);
        let server_only_aad = server == SecurityProtocol::AAD;
        let client_wants_only_cred = (client_requested.contains(SecurityProtocol::HYBRID)
            || client_requested.contains(SecurityProtocol::HYBRID_EX))
            && !client_requested.contains(SecurityProtocol::SSL)
            && !client_requested.contains(SecurityProtocol::RDSTLS)
            && !client_requested.contains(SecurityProtocol::AAD);

        if server_only_aad {
            Err(NegotiationFailureCode::EntraAuthRequiredByServer)
        } else if client_only_rdp && server_has_enhanced {
            Err(NegotiationFailureCode::SslRequiredByServer)
        } else if server_only_rdp {
            Err(NegotiationFailureCode::SslNotAllowedByServer)
        } else if server_has_cred
            && !client_requested.contains(SecurityProtocol::HYBRID)
            && !client_requested.contains(SecurityProtocol::HYBRID_EX)
        {
            Err(NegotiationFailureCode::HybridRequiredByServer)
        } else if !server_has_cred && client_wants_only_cred {
            // Server supports TLS-class protocols (SSL/RDSTLS/AAD) but
            // not CredSSP, while the client asked exclusively for
            // CredSSP. There is no single best-fit code: the spec gap is
            // documented in the surrounding comment. Emit
            // `INCONSISTENT_FLAGS` ("flags sent are inconsistent with the
            // security protocols currently in effect") as the closest
            // generic mismatch code. `SslNotAllowedByServer` is a worse
            // fit because it asserts the server cannot do TLS at all,
            // which is false here.
            Err(NegotiationFailureCode::InconsistentFlags)
        } else {
            // Generic fallback: no intersection at all. The server might
            // genuinely have nothing in common with the client.
            Err(NegotiationFailureCode::SslNotAllowedByServer)
        }
    }

    fn build_response_flags(
        &self,
        client_flags: NegotiationRequestFlags,
    ) -> NegotiationResponseFlags {
        let mut bits: u8 = 0;
        if self.config.extended_client_data_supported {
            bits |= NegotiationResponseFlags::EXTENDED_CLIENT_DATA.bits();
        }
        if self.config.gfx_supported {
            bits |= NegotiationResponseFlags::DYNVC_GFX.bits();
        }
        if self.config.restricted_admin_supported
            && client_flags.contains(NegotiationRequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED)
        {
            bits |= NegotiationResponseFlags::RESTRICTED_ADMIN.bits();
        }
        if self.config.redirected_auth_supported
            && client_flags.contains(NegotiationRequestFlags::REDIRECTED_AUTHENTICATION_MODE_REQUIRED)
        {
            bits |= NegotiationResponseFlags::REDIRECTED_AUTH.bits();
        }
        NegotiationResponseFlags::from_bits(bits)
    }

    // ── Phase 2: TLS Accept (external) ──────────────────────────────────

    /// Caller has finished the TLS server handshake. Transition to the
    /// next phase based on the previously selected security protocol.
    ///
    /// MS-RDPBCGR §5.4.5 — after Enhanced RDP Security has been
    /// established the next PDU on the wire is either a CredSSP TsRequest
    /// (HYBRID/HYBRID_EX) or directly the MCS Connect Initial
    /// (SSL/RDSTLS/AAD).
    fn step_tls_accept(&mut self) -> AcceptorResult<Written> {
        if self.selected_protocol == SecurityProtocol::RDP {
            // Defensive: Standard RDP Security must never reach this state
            // -- `step_send_connection_confirm` already routes RDP
            // straight to `WaitMcsConnectInitial`. Reaching here means a
            // caller has manipulated the state machine.
            return Err(AcceptorError::general(
                "TlsAccept reached with PROTOCOL_RDP -- caller corrupted state",
            ));
        }
        if self.selected_protocol.contains(SecurityProtocol::HYBRID)
            || self.selected_protocol.contains(SecurityProtocol::HYBRID_EX)
        {
            self.state = ServerAcceptorState::CredsspAccept;
        } else {
            // Plain SSL, RDSTLS, or AAD -- the server jumps directly to
            // MCS. RDSTLS / AAD-specific server-side exchanges (if any
            // are added in later commits) should slot in before this
            // transition.
            self.state = ServerAcceptorState::WaitMcsConnectInitial;
        }
        Ok(Written::nothing())
    }

    // ── Phase 4: MCS Connect Initial / Connect Response ────────────────

    fn step_wait_mcs_connect_initial(&mut self, input: &[u8]) -> AcceptorResult<Written> {
        let mut cursor = ReadCursor::new(input);
        let _tpkt = TpktHeader::decode(&mut cursor)?;
        let _dt = DataTransfer::decode(&mut cursor)?;
        let connect_initial = ConnectInitial::decode(&mut cursor)?;

        // Parse client GCC data blocks. The CR/CC happened in plaintext;
        // by here we either reached MCS via TLS+(maybe)CredSSP or via
        // Standard RDP Security. Either way the GCC payload is the same
        // shape on the wire.
        let client_gcc = decode_connect_initial_gcc(&connect_initial.user_data)?;

        // Allocate channel IDs from the client's CS_NET request.
        let client_channels: &[_] = client_gcc
            .network
            .as_ref()
            .map(|n| n.channels.as_slice())
            .unwrap_or(&[]);
        let enable_message_channel = self.config.support_message_channel
            && client_gcc.message_channel.is_some();
        let alloc = allocate_channel_ids(client_channels, enable_message_channel)?;

        // Build server data blocks. For TLS / CredSSP / RDSTLS / AAD the
        // SC_SECURITY block is always "none" (encryption_method=0,
        // encryption_level=0). Standard RDP Security would carry the
        // server random + certificate here; that path requires Commit 1's
        // scaffolding plus a key-derivation step that lives outside the
        // acceptor in justrdp-pdu.
        let multitransport_flags = self
            .config
            .multitransport_flags
            .filter(|_| client_gcc.multitransport.is_some());
        // MS-RDPBCGR §2.2.1.4.2: SC_CORE.clientRequestedProtocols MUST
        // echo the client's original RDP_NEG_REQ.requestedProtocols
        // verbatim so the client can detect a MITM downgrade attack
        // (a MITM that rewrites RDP_NEG_RSP.selectedProtocol can't also
        // forge the SC_CORE echo, because that channel is inside the
        // post-TLS / post-CredSSP stream). Sending the server-chosen
        // protocol instead of the client's request defeats the check.
        let client_requested_protocols = self
            .client_request
            .as_ref()
            .map(|r| r.requested_protocols.bits())
            .unwrap_or(0);
        let inputs = ServerGccInputs {
            server_version: self.config.server_rdp_version,
            client_requested_protocols,
            early_capability_flags: self.config.server_early_capability_flags,
            encryption_method: 0,
            encryption_level: 0,
            server_random: None,
            server_certificate: None,
            channels: &alloc,
            multitransport_flags,
        };
        let server_blocks = build_server_data_blocks(&inputs)?;
        let gcc_resp = wrap_server_gcc(server_blocks)?;

        // Build the MCS Connect Response. `called_connect_id` mirrors the
        // T.125 convention used by Windows servers (always 0).
        let connect_response = ConnectResponse {
            result: ConnectResponseResult::RtSuccessful,
            called_connect_id: 0,
            domain_parameters: DomainParameters::client_default(),
            user_data: gcc_resp,
        };

        // Wrap in TPKT + X.224 DT.
        let inner_size = DATA_TRANSFER_HEADER_SIZE + connect_response.size();
        let total_size = TPKT_HEADER_SIZE + inner_size;
        let mut buf = alloc::vec![0u8; total_size];
        {
            let mut cursor = WriteCursor::new(&mut buf);
            TpktHeader::try_for_payload(inner_size)?.encode(&mut cursor)?;
            DataTransfer.encode(&mut cursor)?;
            connect_response.encode(&mut cursor)?;
        }

        self.client_gcc = Some(client_gcc);
        self.channel_alloc = Some(alloc);
        self.pending_connect_response = Some(buf);
        self.state = ServerAcceptorState::SendMcsConnectResponse;
        Ok(Written::nothing())
    }

    fn step_send_mcs_connect_response(
        &mut self,
        output: &mut WriteBuf,
    ) -> AcceptorResult<Written> {
        let bytes = self.pending_connect_response.take().ok_or_else(|| {
            AcceptorError::general("no pending MCS Connect Response (state machine corrupt)")
        })?;
        output.resize(bytes.len());
        output.as_mut_slice()[..bytes.len()].copy_from_slice(&bytes);
        self.state = ServerAcceptorState::ChannelConnection;
        self.channel_phase = ChannelPhase::WaitErectDomainRequest;
        Ok(Written::new(bytes.len()))
    }

    // ── Phase 5: Channel Connection ────────────────────────────────────

    /// Encode an MCS PER PDU wrapped in TPKT + X.224 DT and write it
    /// into `output`.
    fn write_slow_path(
        &self,
        pdu: &dyn Encode,
        output: &mut WriteBuf,
    ) -> AcceptorResult<usize> {
        let inner = DATA_TRANSFER_HEADER_SIZE + pdu.size();
        let total = TPKT_HEADER_SIZE + inner;
        output.resize(total);
        let mut cursor = WriteCursor::new(output.as_mut_slice());
        TpktHeader::try_for_payload(inner)?.encode(&mut cursor)?;
        DataTransfer.encode(&mut cursor)?;
        pdu.encode(&mut cursor)?;
        Ok(total)
    }

    /// Decode a TPKT + X.224 DT envelope and return a cursor positioned
    /// at the start of the inner PER-encoded MCS PDU.
    fn decode_slow_path<'a>(input: &'a [u8]) -> AcceptorResult<ReadCursor<'a>> {
        let mut cursor = ReadCursor::new(input);
        let _tpkt = TpktHeader::decode(&mut cursor)?;
        let _dt = DataTransfer::decode(&mut cursor)?;
        Ok(cursor)
    }

    /// Compute the user channel ID to assign in `AttachUserConfirm`.
    ///
    /// Convention (matches Windows / FreeRDP servers):
    /// - I/O channel:  `0x03EB` (1003)
    /// - Static VCs:   `0x03EC..` (one per `ClientNetworkData.channels`)
    /// - Message ch.:  next free if `support_message_channel`
    /// - User ch.:     next free, with a floor of `0x03EF` (1007) so
    ///                 even pure-no-static-channel sessions get a user
    ///                 ID in the conventional range.
    fn next_user_channel_id(alloc: &ChannelAllocation) -> u16 {
        let mut next = alloc.io_channel_id + 1 + alloc.static_channels.len() as u16;
        if alloc.message_channel_id.is_some() {
            next += 1;
        }
        next.max(0x03EF)
    }

    fn step_channel_connection(
        &mut self,
        input: &[u8],
        output: &mut WriteBuf,
    ) -> AcceptorResult<Written> {
        match self.channel_phase {
            ChannelPhase::WaitErectDomainRequest => self.step_wait_erect_domain(input),
            ChannelPhase::WaitAttachUserRequest => self.step_wait_attach_user_request(input),
            ChannelPhase::SendAttachUserConfirm => self.step_send_attach_user_confirm(output),
            ChannelPhase::WaitChannelJoinRequest => self.step_wait_channel_join_request(input),
            ChannelPhase::SendChannelJoinConfirm => self.step_send_channel_join_confirm(output),
            ChannelPhase::Done => {
                // All channels joined -- transition into the next phase
                // (Standard RDP Security key exchange would land here in
                // the legacy path; otherwise we go straight to the
                // Secure Settings Exchange in a later commit). For now
                // park in `WaitClientInfo` so future commits can pick
                // up the thread.
                self.state = ServerAcceptorState::WaitClientInfo;
                Ok(Written::nothing())
            }
        }
    }

    fn step_wait_erect_domain(&mut self, input: &[u8]) -> AcceptorResult<Written> {
        let mut cursor = Self::decode_slow_path(input)?;
        let _erect = ErectDomainRequest::decode(&mut cursor)?;
        // Erect Domain has no response. Move straight to AttachUser.
        self.channel_phase = ChannelPhase::WaitAttachUserRequest;
        Ok(Written::nothing())
    }

    fn step_wait_attach_user_request(&mut self, input: &[u8]) -> AcceptorResult<Written> {
        let mut cursor = Self::decode_slow_path(input)?;
        let _aur = AttachUserRequest::decode(&mut cursor)?;

        let alloc = self
            .channel_alloc
            .as_ref()
            .ok_or_else(|| AcceptorError::general("AttachUserRequest before MCS Connect"))?;
        self.user_channel_id = Self::next_user_channel_id(alloc);

        // Build the channel-join list in the order the client will join:
        //   user channel, I/O channel, [message channel], then each
        //   static virtual channel in original order. The client always
        //   joins the user channel first to validate the assignment,
        //   then the I/O channel, then everything else.
        self.channels_to_join.clear();
        self.channels_to_join.push(self.user_channel_id);
        self.channels_to_join.push(alloc.io_channel_id);
        if let Some(msg) = alloc.message_channel_id {
            self.channels_to_join.push(msg);
        }
        for (_, id) in alloc.static_channels.iter() {
            self.channels_to_join.push(*id);
        }
        self.channel_join_index = 0;

        self.channel_phase = ChannelPhase::SendAttachUserConfirm;
        Ok(Written::nothing())
    }

    fn step_send_attach_user_confirm(&mut self, output: &mut WriteBuf) -> AcceptorResult<Written> {
        let confirm = AttachUserConfirm {
            result: 0, // rt-successful
            initiator: Some(self.user_channel_id),
        };
        let written = self.write_slow_path(&confirm, output)?;
        self.channel_phase = ChannelPhase::WaitChannelJoinRequest;
        Ok(Written::new(written))
    }

    fn step_wait_channel_join_request(&mut self, input: &[u8]) -> AcceptorResult<Written> {
        let mut cursor = Self::decode_slow_path(input)?;
        let req = ChannelJoinRequest::decode(&mut cursor)?;

        // MS-RDPBCGR §1.3.1.1.5 does not mandate a specific ordering for
        // client-side Channel Join Requests, but real clients (mstsc,
        // FreeRDP) always follow the order that the server returned in
        // `ServerNetworkData` (user channel first, then I/O, then
        // message, then statics). Enforcing strict order here gives us
        // three things in one check:
        //   1. Rejection of random unallocated channel IDs.
        //   2. Rejection of duplicate joins (same ID sent twice would
        //      pass a plain `contains()` check but would skip an
        //      unjoined channel).
        //   3. Bounds safety against post-Done join requests.
        let expected = *self.channels_to_join.get(self.channel_join_index).ok_or_else(|| {
            AcceptorError::general("ChannelJoinRequest received after all channels joined")
        })?;
        if req.channel_id != expected {
            return Err(AcceptorError::general(
                "ChannelJoinRequest channel_id does not match the next expected channel ID \
                 (out-of-order, unallocated, or duplicate)",
            ));
        }
        // Reject initiator ID that doesn't match the user channel we
        // just assigned (anti-spoofing: any other client on this MCS
        // connection should never appear during the join loop).
        if req.initiator != self.user_channel_id {
            return Err(AcceptorError::general(
                "ChannelJoinRequest initiator does not match assigned user channel ID",
            ));
        }

        // Stash the requested ID; the send step echoes it.
        self.pending_join_requested = Some(req.channel_id);
        self.channel_phase = ChannelPhase::SendChannelJoinConfirm;
        Ok(Written::nothing())
    }

    fn step_send_channel_join_confirm(
        &mut self,
        output: &mut WriteBuf,
    ) -> AcceptorResult<Written> {
        let requested = self.pending_join_requested.take().ok_or_else(|| {
            AcceptorError::general("no pending Channel Join Request")
        })?;
        let confirm = ChannelJoinConfirm {
            result: 0, // rt-successful
            initiator: self.user_channel_id,
            requested,
            channel_id: Some(requested),
        };
        let written = self.write_slow_path(&confirm, output)?;
        self.channel_join_index += 1;
        if self.channel_join_index >= self.channels_to_join.len() {
            self.channel_phase = ChannelPhase::Done;
        } else {
            self.channel_phase = ChannelPhase::WaitChannelJoinRequest;
        }
        Ok(Written::new(written))
    }

    // ── Phase 3: CredSSP Accept (external) ──────────────────────────────

    /// Caller has finished the server-side CredSSP exchange (NEGOTIATE /
    /// CHALLENGE / AUTHENTICATE / TSCredentials). For HYBRID_EX the
    /// caller is also responsible for emitting the 4-byte
    /// EarlyUserAuthResult (MS-RDPBCGR §5.4.2.2) on the TLS stream
    /// **before** invoking `step()` -- this state machine does not
    /// produce that byte sequence.
    ///
    /// MS-CSSP §3.1.5 leaves the actual SPNEGO/NTLM exchange to the
    /// caller's `ServerCredsspSequence` (mirrors the way the client
    /// `Connector` defers to `CredsspSequence`). The state machine just
    /// records that auth completed and moves on.
    fn step_credssp_accept(&mut self) -> AcceptorResult<Written> {
        self.state = ServerAcceptorState::WaitMcsConnectInitial;
        Ok(Written::nothing())
    }

    // ── External-failure helpers ────────────────────────────────────────

    /// Caller signals that the external TLS handshake failed. The
    /// acceptor transitions to `NegotiationFailed`; no Connection
    /// Confirm is emitted (one was already sent and the failure is
    /// purely TLS-layer). The caller must close the underlying TCP
    /// connection.
    pub fn notify_tls_failed(&mut self) -> AcceptorResult<()> {
        match self.state {
            ServerAcceptorState::TlsAccept => {
                self.state = ServerAcceptorState::NegotiationFailed;
                Ok(())
            }
            _ => Err(AcceptorError {
                kind: AcceptorErrorKind::InvalidState,
            }),
        }
    }

    /// Caller signals that the external server-side CredSSP exchange
    /// failed (auth rejected, pubKeyAuth verification failed, etc.).
    /// The acceptor transitions to `NegotiationFailed`. The caller is
    /// expected to have already emitted any spec-mandated error PDU
    /// (e.g. TsRequest with `errorCode`, EarlyUserAuthResult =
    /// `ACCESS_DENIED` for HYBRID_EX) on the TLS stream before invoking
    /// this helper.
    pub fn notify_credssp_failed(&mut self) -> AcceptorResult<()> {
        match self.state {
            ServerAcceptorState::CredsspAccept => {
                self.state = ServerAcceptorState::NegotiationFailed;
                Ok(())
            }
            _ => Err(AcceptorError {
                kind: AcceptorErrorKind::InvalidState,
            }),
        }
    }

    /// Build the final [`AcceptanceResult`]. Phase 1 stops before the full
    /// connection completes; this method exists for tests and for the
    /// completion path that later phases (Commits 4 / 6 / 7) will wire up.
    #[allow(dead_code)] // Wired up in later commits.
    pub(crate) fn make_acceptance_result(&self) -> AcceptanceResult {
        let info = self
            .client_request
            .clone()
            .unwrap_or_else(ClientRequestInfo::legacy);
        let mut result = AcceptanceResult::new(info);
        result.selected_protocol = self.selected_protocol;
        result.server_nego_flags = self.server_nego_flags;
        if let Some(alloc) = &self.channel_alloc {
            result.io_channel_id = alloc.io_channel_id;
            result.channel_ids = alloc.static_channels.clone();
        }
        result
    }
}

impl AcceptorConfig {
    /// Convenience: does this config advertise the given protocol?
    fn supports_protocol(&self, p: SecurityProtocol) -> bool {
        if p == SecurityProtocol::RDP {
            // PROTOCOL_RDP is the absence of enhanced bits; it's
            // "supported" iff the policy allows it.
            !self.require_enhanced_security
        } else {
            self.supported_protocols.contains(p)
        }
    }
}

impl Sequence for ServerAcceptor {
    fn state(&self) -> &ServerAcceptorState {
        &self.state
    }

    fn next_pdu_hint(&self) -> Option<&dyn PduHint> {
        match self.state {
            ServerAcceptorState::WaitConnectionRequest => Some(&TPKT_HINT),
            ServerAcceptorState::SendConnectionConfirm => None,
            ServerAcceptorState::TlsAccept => None,
            ServerAcceptorState::CredsspAccept => None,
            ServerAcceptorState::WaitMcsConnectInitial => Some(&TPKT_HINT),
            ServerAcceptorState::SendMcsConnectResponse => None,
            ServerAcceptorState::ChannelConnection => match self.channel_phase {
                ChannelPhase::WaitErectDomainRequest
                | ChannelPhase::WaitAttachUserRequest
                | ChannelPhase::WaitChannelJoinRequest => Some(&TPKT_HINT),
                ChannelPhase::SendAttachUserConfirm
                | ChannelPhase::SendChannelJoinConfirm
                | ChannelPhase::Done => None,
            },
            ServerAcceptorState::WaitClientInfo => Some(&TPKT_HINT),
            ServerAcceptorState::SendLicense => None,
            ServerAcceptorState::SendDemandActive => None,
            ServerAcceptorState::WaitConfirmActive => Some(&TPKT_HINT),
            ServerAcceptorState::ConnectionFinalization => Some(&TPKT_HINT),
            ServerAcceptorState::Accepted { .. } | ServerAcceptorState::NegotiationFailed => None,
        }
    }

    fn step(&mut self, input: &[u8], output: &mut WriteBuf) -> AcceptorResult<Written> {
        match self.state {
            ServerAcceptorState::WaitConnectionRequest => {
                self.step_wait_connection_request(input)
            }
            ServerAcceptorState::SendConnectionConfirm => self.step_send_connection_confirm(output),
            ServerAcceptorState::TlsAccept => self.step_tls_accept(),
            ServerAcceptorState::CredsspAccept => self.step_credssp_accept(),
            ServerAcceptorState::WaitMcsConnectInitial => {
                self.step_wait_mcs_connect_initial(input)
            }
            ServerAcceptorState::SendMcsConnectResponse => {
                self.step_send_mcs_connect_response(output)
            }
            ServerAcceptorState::ChannelConnection => {
                self.step_channel_connection(input, output)
            }
            // Later commits will fill these in.
            ServerAcceptorState::WaitClientInfo
            | ServerAcceptorState::SendLicense
            | ServerAcceptorState::SendDemandActive
            | ServerAcceptorState::WaitConfirmActive
            | ServerAcceptorState::ConnectionFinalization => Err(AcceptorError::general(
                "state not yet implemented in this commit",
            )),
            ServerAcceptorState::Accepted { .. } | ServerAcceptorState::NegotiationFailed => {
                Err(AcceptorError {
                    kind: AcceptorErrorKind::InvalidState,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_core::Encode;
    use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
    use justrdp_pdu::x224::{
        ConnectionConfirmNegotiation, ConnectionRequest, NegotiationFailureCode,
        NegotiationRequest, SecurityProtocol,
    };

    /// Encode a TPKT-wrapped CR for tests.
    fn build_cr_bytes(cr: &ConnectionRequest) -> alloc::vec::Vec<u8> {
        let total = TPKT_HEADER_SIZE + cr.size();
        let mut buf = alloc::vec![0u8; total];
        let mut cursor = justrdp_core::WriteCursor::new(&mut buf);
        TpktHeader::try_for_payload(cr.size())
            .unwrap()
            .encode(&mut cursor)
            .unwrap();
        cr.encode(&mut cursor).unwrap();
        buf
    }

    fn decode_cc_from_buf(buf: &[u8]) -> ConnectionConfirm {
        let mut cursor = ReadCursor::new(buf);
        let _tpkt = TpktHeader::decode(&mut cursor).unwrap();
        ConnectionConfirm::decode(&mut cursor).unwrap()
    }

    #[test]
    fn initial_state_is_wait_connection_request() {
        let acc = ServerAcceptor::new(AcceptorConfig::default());
        assert_eq!(acc.state(), &ServerAcceptorState::WaitConnectionRequest);
        assert!(acc.next_pdu_hint().is_some());
    }

    #[test]
    fn hybrid_request_selects_hybrid() {
        // Modern Windows client: requestedProtocols = SSL | HYBRID
        let nego = NegotiationRequest::new(
            SecurityProtocol::SSL.union(SecurityProtocol::HYBRID),
        );
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let mut acc = ServerAcceptor::new(AcceptorConfig::default());
        let mut out = WriteBuf::new();

        // 1) WaitConnectionRequest -> SendConnectionConfirm
        acc.step(&cr_bytes, &mut out).unwrap();
        assert_eq!(acc.state(), &ServerAcceptorState::SendConnectionConfirm);
        assert!(out.is_empty());

        // 2) SendConnectionConfirm produces the wire bytes and transitions
        //    to TlsAccept (HYBRID requires TLS).
        let written = acc.step(&[], &mut out).unwrap();
        assert!(written.size > 0);
        assert_eq!(acc.state(), &ServerAcceptorState::TlsAccept);

        let cc = decode_cc_from_buf(&out.as_slice()[..written.size]);
        match cc.negotiation {
            Some(ConnectionConfirmNegotiation::Response(r)) => {
                assert_eq!(r.protocol, SecurityProtocol::HYBRID);
                assert!(r
                    .flags
                    .contains(NegotiationResponseFlags::EXTENDED_CLIENT_DATA));
            }
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[test]
    fn hybrid_ex_takes_priority_over_hybrid() {
        let nego = NegotiationRequest::new(
            SecurityProtocol::SSL
                .union(SecurityProtocol::HYBRID)
                .union(SecurityProtocol::HYBRID_EX),
        );
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let mut acc = ServerAcceptor::new(AcceptorConfig::default());
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let written = acc.step(&[], &mut out).unwrap();
        let cc = decode_cc_from_buf(&out.as_slice()[..written.size]);
        match cc.negotiation {
            Some(ConnectionConfirmNegotiation::Response(r)) => {
                assert_eq!(r.protocol, SecurityProtocol::HYBRID_EX);
            }
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[test]
    fn rdp_only_request_returns_ssl_required_when_server_requires_enhanced() {
        let nego = NegotiationRequest::new(SecurityProtocol::RDP);
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        // Default config has require_enhanced_security = true.
        let mut acc = ServerAcceptor::new(AcceptorConfig::default());
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let err = acc.step(&[], &mut out).unwrap_err();
        match err.kind {
            AcceptorErrorKind::NegotiationFailed(NegotiationFailureCode::SslRequiredByServer) => {}
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(acc.state(), &ServerAcceptorState::NegotiationFailed);

        let cc = decode_cc_from_buf(out.as_slice());
        match cc.negotiation {
            Some(ConnectionConfirmNegotiation::Failure(f)) => {
                assert_eq!(f.code, NegotiationFailureCode::SslRequiredByServer);
            }
            other => panic!("expected failure, got {other:?}"),
        }
    }

    #[test]
    fn rdp_only_request_succeeds_when_server_allows_legacy() {
        let nego = NegotiationRequest::new(SecurityProtocol::RDP);
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let cfg = AcceptorConfig::builder()
            .require_enhanced_security(false)
            .supported_protocols(SecurityProtocol::RDP)
            .build();
        let mut acc = ServerAcceptor::new(cfg);
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let written = acc.step(&[], &mut out).unwrap();
        assert!(written.size > 0);
        // RDP-only path goes straight to MCS, not TLS.
        assert_eq!(acc.state(), &ServerAcceptorState::WaitMcsConnectInitial);
        let cc = decode_cc_from_buf(&out.as_slice()[..written.size]);
        match cc.negotiation {
            Some(ConnectionConfirmNegotiation::Response(r)) => {
                assert_eq!(r.protocol, SecurityProtocol::RDP);
            }
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[test]
    fn ssl_only_request_with_cred_required_server_returns_hybrid_required() {
        let nego = NegotiationRequest::new(SecurityProtocol::SSL);
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        // Server only advertises HYBRID/HYBRID_EX (no plain SSL).
        let cfg = AcceptorConfig::builder()
            .supported_protocols(
                SecurityProtocol::HYBRID.union(SecurityProtocol::HYBRID_EX),
            )
            .build();
        let mut acc = ServerAcceptor::new(cfg);
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let err = acc.step(&[], &mut out).unwrap_err();
        match err.kind {
            AcceptorErrorKind::NegotiationFailed(
                NegotiationFailureCode::HybridRequiredByServer,
            ) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn missing_certificate_emits_ssl_cert_not_on_server() {
        let nego = NegotiationRequest::new(SecurityProtocol::SSL);
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let cfg = AcceptorConfig::builder()
            .tls_certificate_available(false)
            .build();
        let mut acc = ServerAcceptor::new(cfg);
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let err = acc.step(&[], &mut out).unwrap_err();
        match err.kind {
            AcceptorErrorKind::NegotiationFailed(NegotiationFailureCode::SslCertNotOnServer) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn legacy_cr_without_neg_req_emits_legacy_cc() {
        // Build a CR without `RDP_NEG_REQ` (legacy RDP 4.x/5.0 client).
        let cr = ConnectionRequest::new(None);
        let cr_bytes = build_cr_bytes(&cr);

        let cfg = AcceptorConfig::builder()
            .require_enhanced_security(false)
            .supported_protocols(SecurityProtocol::RDP)
            .build();
        let mut acc = ServerAcceptor::new(cfg);
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let written = acc.step(&[], &mut out).unwrap();
        assert!(written.size > 0);
        // Legacy CC: 4-byte TPKT + 7-byte X.224 CC fixed header = 11 bytes.
        assert_eq!(written.size, 11);

        let info = acc.client_request().unwrap();
        assert!(!info.had_negotiation_request);
        assert_eq!(info.requested_protocols, SecurityProtocol::RDP);
    }

    #[test]
    fn restricted_admin_flag_is_echoed_when_supported() {
        let nego = NegotiationRequest::with_flags(
            SecurityProtocol::HYBRID,
            NegotiationRequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED,
        );
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let cfg = AcceptorConfig::builder()
            .restricted_admin_supported(true)
            .build();
        let mut acc = ServerAcceptor::new(cfg);
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let written = acc.step(&[], &mut out).unwrap();
        let cc = decode_cc_from_buf(&out.as_slice()[..written.size]);
        match cc.negotiation {
            Some(ConnectionConfirmNegotiation::Response(r)) => {
                assert!(r.flags.contains(NegotiationResponseFlags::RESTRICTED_ADMIN));
            }
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[test]
    fn restricted_admin_flag_not_echoed_when_unsupported_by_config() {
        let nego = NegotiationRequest::with_flags(
            SecurityProtocol::HYBRID,
            NegotiationRequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED,
        );
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        // restricted_admin_supported = false (default).
        let mut acc = ServerAcceptor::new(AcceptorConfig::default());
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let written = acc.step(&[], &mut out).unwrap();
        let cc = decode_cc_from_buf(&out.as_slice()[..written.size]);
        match cc.negotiation {
            Some(ConnectionConfirmNegotiation::Response(r)) => {
                assert!(!r.flags.contains(NegotiationResponseFlags::RESTRICTED_ADMIN));
            }
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[test]
    fn entra_required_when_server_only_supports_aad() {
        let nego = NegotiationRequest::new(SecurityProtocol::HYBRID);
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let cfg = AcceptorConfig::builder()
            .supported_protocols(SecurityProtocol::AAD)
            .build();
        let mut acc = ServerAcceptor::new(cfg);
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let err = acc.step(&[], &mut out).unwrap_err();
        match err.kind {
            AcceptorErrorKind::NegotiationFailed(
                NegotiationFailureCode::EntraAuthRequiredByServer,
            ) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn cookie_is_captured_from_cr() {
        let nego = NegotiationRequest::new(SecurityProtocol::HYBRID);
        let cr = ConnectionRequest::with_cookie(alloc::string::String::from("eltons"), Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let mut acc = ServerAcceptor::new(AcceptorConfig::default());
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let _ = acc.step(&[], &mut out).unwrap();
        let info = acc.client_request().unwrap();
        assert_eq!(info.cookie.as_deref(), Some("eltons"));
        assert!(info.routing_token.is_none());
    }

    #[test]
    fn routing_token_is_captured_from_cr() {
        let nego = NegotiationRequest::new(SecurityProtocol::HYBRID);
        let cr = ConnectionRequest::with_routing_token(alloc::vec![0xAA, 0xBB, 0xCC], Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let mut acc = ServerAcceptor::new(AcceptorConfig::default());
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let _ = acc.step(&[], &mut out).unwrap();
        let info = acc.client_request().unwrap();
        assert_eq!(info.routing_token.as_deref(), Some(&[0xAA_u8, 0xBB, 0xCC][..]));
        assert!(info.cookie.is_none());
    }

    #[test]
    fn known_answer_hybrid_response_wire_bytes() {
        // CR: requestedProtocols = SSL|HYBRID = 0x3
        // Spec §4.1.1-style wire bytes (with no cookie):
        //   03 00 00 13   0e e0 00 00 00 00 00   01 00 08 00  03 00 00 00
        let cr_bytes: alloc::vec::Vec<u8> = alloc::vec![
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
            0x00, 0x03, 0x00, 0x00, 0x00,
        ];

        // Default server config: supports SSL|HYBRID|HYBRID_EX, extended-client-data flag set.
        let mut acc = ServerAcceptor::new(AcceptorConfig::default());
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let written = acc.step(&[], &mut out).unwrap();
        // Expected CC: TPKT(03 00 00 13) + X.224 CC(0e d0 00 00 00 00 00) +
        //              RDP_NEG_RSP(02 01 08 00 02 00 00 00).
        // flags = EXTENDED_CLIENT_DATA(0x01); protocol = HYBRID(0x02).
        let expected: alloc::vec::Vec<u8> = alloc::vec![
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x08,
            0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        assert_eq!(&out.as_slice()[..written.size], expected.as_slice());
    }

    #[test]
    fn redirected_auth_flag_is_echoed_when_supported() {
        let nego = NegotiationRequest::with_flags(
            SecurityProtocol::HYBRID,
            NegotiationRequestFlags::REDIRECTED_AUTHENTICATION_MODE_REQUIRED,
        );
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let cfg = AcceptorConfig::builder()
            .redirected_auth_supported(true)
            .build();
        let mut acc = ServerAcceptor::new(cfg);
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let written = acc.step(&[], &mut out).unwrap();
        let cc = decode_cc_from_buf(&out.as_slice()[..written.size]);
        match cc.negotiation {
            Some(ConnectionConfirmNegotiation::Response(r)) => {
                assert!(r.flags.contains(NegotiationResponseFlags::REDIRECTED_AUTH));
            }
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[test]
    fn redirected_auth_flag_not_echoed_when_unsupported_by_config() {
        let nego = NegotiationRequest::with_flags(
            SecurityProtocol::HYBRID,
            NegotiationRequestFlags::REDIRECTED_AUTHENTICATION_MODE_REQUIRED,
        );
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let mut acc = ServerAcceptor::new(AcceptorConfig::default());
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let written = acc.step(&[], &mut out).unwrap();
        let cc = decode_cc_from_buf(&out.as_slice()[..written.size]);
        match cc.negotiation {
            Some(ConnectionConfirmNegotiation::Response(r)) => {
                assert!(!r.flags.contains(NegotiationResponseFlags::REDIRECTED_AUTH));
            }
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[test]
    fn dynvc_gfx_flag_is_set_when_supported() {
        let nego = NegotiationRequest::new(SecurityProtocol::HYBRID);
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let cfg = AcceptorConfig::builder().gfx_supported(true).build();
        let mut acc = ServerAcceptor::new(cfg);
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let written = acc.step(&[], &mut out).unwrap();
        let cc = decode_cc_from_buf(&out.as_slice()[..written.size]);
        match cc.negotiation {
            Some(ConnectionConfirmNegotiation::Response(r)) => {
                assert!(r.flags.contains(NegotiationResponseFlags::DYNVC_GFX));
            }
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[test]
    fn server_with_ssl_only_and_client_wanting_only_cred_returns_inconsistent_flags() {
        // Spec gap: server has SSL+AAD (no CredSSP), client requests
        // only HYBRID. SslNotAllowedByServer would be misleading because
        // the server *does* allow TLS; HybridRequiredByServer would be
        // wrong because the server *cannot* offer CredSSP. We emit
        // INCONSISTENT_FLAGS as the closest available code.
        let nego = NegotiationRequest::new(SecurityProtocol::HYBRID);
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let cfg = AcceptorConfig::builder()
            .supported_protocols(SecurityProtocol::SSL.union(SecurityProtocol::AAD))
            .build();
        let mut acc = ServerAcceptor::new(cfg);
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let err = acc.step(&[], &mut out).unwrap_err();
        match err.kind {
            AcceptorErrorKind::NegotiationFailed(NegotiationFailureCode::InconsistentFlags) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn output_is_populated_even_on_negotiation_failure() {
        // The caller must be able to flush `output` before consuming the
        // error -- without this guarantee the client never sees the
        // RDP_NEG_FAILURE PDU.
        let nego = NegotiationRequest::new(SecurityProtocol::RDP);
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let mut acc = ServerAcceptor::new(AcceptorConfig::default());
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let _err = acc.step(&[], &mut out).unwrap_err();
        // 4-byte TPKT + 7-byte X.224 CC fixed header + 8-byte RDP_NEG_FAILURE.
        assert_eq!(out.len(), 19);
        assert_eq!(out.as_slice()[5], 0xd0); // X.224 CC code
        assert_eq!(out.as_slice()[11], 0x03); // RDP_NEG_FAILURE type
    }

    /// Drive the acceptor from `WaitConnectionRequest` through the CC
    /// using a CR that requests `client_request_proto`. Returns the
    /// acceptor in whatever state it lands in after `SendConnectionConfirm`.
    fn drive_through_cc(client_request_proto: SecurityProtocol) -> ServerAcceptor {
        let nego = NegotiationRequest::new(client_request_proto);
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);
        let mut acc = ServerAcceptor::new(AcceptorConfig::default());
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let _ = acc.step(&[], &mut out).unwrap();
        acc
    }

    #[test]
    fn tls_accept_with_hybrid_transitions_to_credssp_accept() {
        let mut acc = drive_through_cc(SecurityProtocol::HYBRID);
        assert_eq!(acc.state(), &ServerAcceptorState::TlsAccept);
        let mut out = WriteBuf::new();
        let written = acc.step(&[], &mut out).unwrap();
        assert_eq!(written.size, 0);
        assert_eq!(acc.state(), &ServerAcceptorState::CredsspAccept);
    }

    #[test]
    fn tls_accept_with_hybrid_ex_transitions_to_credssp_accept() {
        let mut acc =
            drive_through_cc(SecurityProtocol::SSL.union(SecurityProtocol::HYBRID_EX));
        assert_eq!(acc.state(), &ServerAcceptorState::TlsAccept);
        let mut out = WriteBuf::new();
        acc.step(&[], &mut out).unwrap();
        assert_eq!(acc.state(), &ServerAcceptorState::CredsspAccept);
    }

    #[test]
    fn tls_accept_with_ssl_skips_credssp() {
        // Server config that does not advertise HYBRID/HYBRID_EX so the
        // client's SSL-only request is honoured as plain SSL.
        let cfg = AcceptorConfig::builder()
            .supported_protocols(SecurityProtocol::SSL)
            .build();
        let nego = NegotiationRequest::new(SecurityProtocol::SSL);
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);
        let mut acc = ServerAcceptor::new(cfg);
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        acc.step(&[], &mut out).unwrap();
        assert_eq!(acc.state(), &ServerAcceptorState::TlsAccept);
        acc.step(&[], &mut out).unwrap();
        assert_eq!(acc.state(), &ServerAcceptorState::WaitMcsConnectInitial);
    }

    #[test]
    fn credssp_accept_transitions_to_wait_mcs_connect_initial() {
        let mut acc = drive_through_cc(SecurityProtocol::HYBRID);
        let mut out = WriteBuf::new();
        // TlsAccept -> CredsspAccept
        acc.step(&[], &mut out).unwrap();
        assert_eq!(acc.state(), &ServerAcceptorState::CredsspAccept);
        // CredsspAccept -> WaitMcsConnectInitial
        let written = acc.step(&[], &mut out).unwrap();
        assert_eq!(written.size, 0);
        assert_eq!(acc.state(), &ServerAcceptorState::WaitMcsConnectInitial);
    }

    #[test]
    fn notify_tls_failed_transitions_to_negotiation_failed() {
        let mut acc = drive_through_cc(SecurityProtocol::HYBRID);
        assert_eq!(acc.state(), &ServerAcceptorState::TlsAccept);
        acc.notify_tls_failed().unwrap();
        assert_eq!(acc.state(), &ServerAcceptorState::NegotiationFailed);
    }

    #[test]
    fn notify_credssp_failed_transitions_to_negotiation_failed() {
        let mut acc = drive_through_cc(SecurityProtocol::HYBRID);
        let mut out = WriteBuf::new();
        acc.step(&[], &mut out).unwrap(); // -> CredsspAccept
        acc.notify_credssp_failed().unwrap();
        assert_eq!(acc.state(), &ServerAcceptorState::NegotiationFailed);
    }

    #[test]
    fn notify_tls_failed_in_wrong_state_errors() {
        // Fresh acceptor in WaitConnectionRequest; calling notify_tls_failed
        // is a programming error.
        let mut acc = ServerAcceptor::new(AcceptorConfig::default());
        let err = acc.notify_tls_failed().unwrap_err();
        assert!(matches!(err.kind, AcceptorErrorKind::InvalidState));
    }

    #[test]
    fn notify_credssp_failed_in_wrong_state_errors() {
        let mut acc = ServerAcceptor::new(AcceptorConfig::default());
        let err = acc.notify_credssp_failed().unwrap_err();
        assert!(matches!(err.kind, AcceptorErrorKind::InvalidState));
    }

    #[test]
    fn notify_credssp_failed_called_in_tls_accept_state_errors() {
        // Cross-state guard: must not silently accept the wrong helper.
        let mut acc = drive_through_cc(SecurityProtocol::HYBRID);
        assert_eq!(acc.state(), &ServerAcceptorState::TlsAccept);
        let err = acc.notify_credssp_failed().unwrap_err();
        assert!(matches!(err.kind, AcceptorErrorKind::InvalidState));
        assert_eq!(acc.state(), &ServerAcceptorState::TlsAccept);
    }

    #[test]
    fn notify_tls_failed_called_in_credssp_accept_state_errors() {
        let mut acc = drive_through_cc(SecurityProtocol::HYBRID);
        let mut out = WriteBuf::new();
        acc.step(&[], &mut out).unwrap(); // -> CredsspAccept
        let err = acc.notify_tls_failed().unwrap_err();
        assert!(matches!(err.kind, AcceptorErrorKind::InvalidState));
        assert_eq!(acc.state(), &ServerAcceptorState::CredsspAccept);
    }

    /// Build a TPKT-wrapped MCS Connect Initial with the given GCC client
    /// data blocks.
    fn build_mcs_connect_initial_bytes(client_blocks: &[u8]) -> alloc::vec::Vec<u8> {
        use justrdp_pdu::gcc::ConferenceCreateRequest;
        use justrdp_pdu::mcs::{ConnectInitial, DomainParameters};
        use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
        use justrdp_pdu::x224::{DataTransfer, DATA_TRANSFER_HEADER_SIZE};

        let gcc = ConferenceCreateRequest::new(client_blocks.to_vec());
        let gcc_encoded = justrdp_core::encode_vec(&gcc).unwrap();

        let ci = ConnectInitial {
            calling_domain_selector: alloc::vec![1],
            called_domain_selector: alloc::vec![1],
            upward_flag: true,
            target_parameters: DomainParameters::client_default(),
            minimum_parameters: DomainParameters::min_default(),
            maximum_parameters: DomainParameters::max_default(),
            user_data: gcc_encoded,
        };
        let inner_size = DATA_TRANSFER_HEADER_SIZE + ci.size();
        let total = TPKT_HEADER_SIZE + inner_size;
        let mut buf = alloc::vec![0u8; total];
        let mut cursor = justrdp_core::WriteCursor::new(&mut buf);
        TpktHeader::try_for_payload(inner_size).unwrap().encode(&mut cursor).unwrap();
        DataTransfer.encode(&mut cursor).unwrap();
        ci.encode(&mut cursor).unwrap();
        buf
    }

    /// Build the minimal client GCC user data: CS_CORE + CS_SECURITY +
    /// optional CS_NET.
    fn build_client_gcc_blocks(channels: &[&str]) -> alloc::vec::Vec<u8> {
        use justrdp_pdu::gcc::client::{
            ChannelDef, ClientCoreData, ClientNetworkData, ClientSecurityData,
        };
        let core = ClientCoreData::new(1024, 768);
        let security = ClientSecurityData::new();
        let mut total = core.size() + security.size();
        let net = if !channels.is_empty() {
            let chans: alloc::vec::Vec<ChannelDef> = channels
                .iter()
                .map(|n| ChannelDef::new(n, 0))
                .collect();
            let n = ClientNetworkData { channels: chans };
            total += n.size();
            Some(n)
        } else {
            None
        };
        let mut buf = alloc::vec![0u8; total];
        let mut cursor = justrdp_core::WriteCursor::new(&mut buf);
        core.encode(&mut cursor).unwrap();
        security.encode(&mut cursor).unwrap();
        if let Some(n) = net {
            n.encode(&mut cursor).unwrap();
        }
        buf
    }

    /// Drive the acceptor through Phase 1, 2, 3 to reach
    /// WaitMcsConnectInitial. Uses an `SSL | HYBRID` negotiation so the
    /// transcript also exercises TLS+CredSSP no-op transitions and lets
    /// callers verify the server echoes the *client's original*
    /// `requestedProtocols` (not the server-chosen `HYBRID`).
    fn drive_to_wait_mcs() -> ServerAcceptor {
        let mut acc = drive_through_cc(
            SecurityProtocol::SSL.union(SecurityProtocol::HYBRID),
        );
        let mut out = WriteBuf::new();
        acc.step(&[], &mut out).unwrap(); // TlsAccept -> CredsspAccept
        acc.step(&[], &mut out).unwrap(); // CredsspAccept -> WaitMcsConnectInitial
        acc
    }

    #[test]
    fn mcs_connect_initial_decode_and_response_round_trip() {
        let mut acc = drive_to_wait_mcs();
        let client_blocks = build_client_gcc_blocks(&["rdpdr", "rdpsnd"]);
        let ci_bytes = build_mcs_connect_initial_bytes(&client_blocks);

        let mut out = WriteBuf::new();
        // WaitMcsConnectInitial
        acc.step(&ci_bytes, &mut out).unwrap();
        assert_eq!(acc.state(), &ServerAcceptorState::SendMcsConnectResponse);
        assert!(out.is_empty());
        let alloc = acc.channel_allocation().unwrap();
        assert_eq!(alloc.io_channel_id, crate::mcs::IO_CHANNEL_ID);
        assert_eq!(alloc.static_channels.len(), 2);
        assert_eq!(alloc.static_channels[0].0, "rdpdr");
        assert_eq!(alloc.static_channels[1].0, "rdpsnd");

        // SendMcsConnectResponse
        let written = acc.step(&[], &mut out).unwrap();
        assert!(written.size > 0);
        assert_eq!(acc.state(), &ServerAcceptorState::ChannelConnection);

        // Verify the produced bytes round-trip through the client decoder.
        let mut cursor = ReadCursor::new(&out.as_slice()[..written.size]);
        let _tpkt = TpktHeader::decode(&mut cursor).unwrap();
        let _dt = DataTransfer::decode(&mut cursor).unwrap();
        let cresp = ConnectResponse::decode(&mut cursor).unwrap();
        assert_eq!(cresp.result, ConnectResponseResult::RtSuccessful);
        // Decode the GCC payload to verify channel IDs match the allocation.
        use justrdp_pdu::gcc::ConferenceCreateResponse;
        let mut gcc_cursor = ReadCursor::new(&cresp.user_data);
        let gcc = ConferenceCreateResponse::decode(&mut gcc_cursor).unwrap();
        // Walk the server data blocks looking for SC_NET.
        let mut block_cursor = ReadCursor::new(&gcc.user_data);
        // Skip SC_CORE (header + version + 2 optional u32s = 16 bytes).
        let core = justrdp_pdu::gcc::server::ServerCoreData::decode(&mut block_cursor).unwrap();
        // Spec §2.2.1.4.2: must echo the client's original
        // requestedProtocols (SSL | HYBRID = 0x3), not the
        // server-selected protocol (HYBRID = 0x2). This catches MITM
        // downgrade attempts.
        assert_eq!(
            core.client_requested_protocols,
            Some(SecurityProtocol::SSL.union(SecurityProtocol::HYBRID).bits())
        );
        // SC_SECURITY
        let _sec = justrdp_pdu::gcc::server::ServerSecurityData::decode(&mut block_cursor).unwrap();
        // SC_NET
        let net =
            justrdp_pdu::gcc::server::ServerNetworkData::decode(&mut block_cursor).unwrap();
        assert_eq!(net.mcs_channel_id, crate::mcs::IO_CHANNEL_ID);
        assert_eq!(
            net.channel_ids,
            alloc::vec![crate::mcs::IO_CHANNEL_ID + 1, crate::mcs::IO_CHANNEL_ID + 2]
        );
    }

    #[test]
    fn mcs_connect_initial_with_message_channel() {
        // Client requests message channel via CS_MCS_MSGCHANNEL.
        use justrdp_pdu::gcc::client::{
            ClientCoreData, ClientMessageChannelData, ClientSecurityData,
        };
        let core = ClientCoreData::new(800, 600);
        let security = ClientSecurityData::new();
        let msg = ClientMessageChannelData { flags: 0 };
        let mut buf = alloc::vec![0u8; core.size() + security.size() + msg.size()];
        let mut cursor = justrdp_core::WriteCursor::new(&mut buf);
        core.encode(&mut cursor).unwrap();
        security.encode(&mut cursor).unwrap();
        msg.encode(&mut cursor).unwrap();
        let ci_bytes = build_mcs_connect_initial_bytes(&buf);

        // Server config that supports the message channel.
        let cfg = AcceptorConfig::builder()
            .support_message_channel(true)
            .build();
        let mut acc = ServerAcceptor::new(cfg);
        let mut out = WriteBuf::new();
        // Drive through CC + TLS + CredSSP.
        let nego = NegotiationRequest::new(SecurityProtocol::HYBRID);
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);
        acc.step(&cr_bytes, &mut out).unwrap();
        acc.step(&[], &mut out).unwrap();
        acc.step(&[], &mut out).unwrap();
        acc.step(&[], &mut out).unwrap();
        // WaitMcsConnectInitial
        acc.step(&ci_bytes, &mut out).unwrap();
        let alloc = acc.channel_allocation().unwrap();
        assert_eq!(alloc.message_channel_id, Some(crate::mcs::IO_CHANNEL_ID + 1));

        // Verify SC_MCS_MSGCHANNEL is in the response.
        let written = acc.step(&[], &mut out).unwrap();
        let mut c = ReadCursor::new(&out.as_slice()[..written.size]);
        let _ = TpktHeader::decode(&mut c).unwrap();
        let _ = DataTransfer::decode(&mut c).unwrap();
        let cresp = ConnectResponse::decode(&mut c).unwrap();
        use justrdp_pdu::gcc::ConferenceCreateResponse;
        let mut gc = ReadCursor::new(&cresp.user_data);
        let gcc = ConferenceCreateResponse::decode(&mut gc).unwrap();
        let mut bc = ReadCursor::new(&gcc.user_data);
        let _core = justrdp_pdu::gcc::server::ServerCoreData::decode(&mut bc).unwrap();
        let _sec = justrdp_pdu::gcc::server::ServerSecurityData::decode(&mut bc).unwrap();
        let _net = justrdp_pdu::gcc::server::ServerNetworkData::decode(&mut bc).unwrap();
        let msg_block =
            justrdp_pdu::gcc::server::ServerMessageChannelData::decode(&mut bc).unwrap();
        assert_eq!(msg_block.mcs_message_channel_id, crate::mcs::IO_CHANNEL_ID + 1);
    }

    #[test]
    fn mcs_connect_initial_no_static_channels_allocates_io_only() {
        let mut acc = drive_to_wait_mcs();
        let client_blocks = build_client_gcc_blocks(&[]);
        let ci_bytes = build_mcs_connect_initial_bytes(&client_blocks);
        let mut out = WriteBuf::new();
        acc.step(&ci_bytes, &mut out).unwrap();
        let alloc = acc.channel_allocation().unwrap();
        assert!(alloc.static_channels.is_empty());
        assert_eq!(alloc.io_channel_id, crate::mcs::IO_CHANNEL_ID);
    }

    #[test]
    fn mcs_connect_initial_rejects_missing_core() {
        let mut acc = drive_to_wait_mcs();
        // Empty client data blocks (no CS_CORE).
        let ci_bytes = build_mcs_connect_initial_bytes(&[]);
        let mut out = WriteBuf::new();
        let err = acc.step(&ci_bytes, &mut out).unwrap_err();
        assert!(alloc::format!("{err}").contains("CS_CORE"));
    }

    /// Helper: encode an MCS PER PDU wrapped in TPKT + X.224 DT.
    fn build_slow_path<P: justrdp_core::Encode>(pdu: &P) -> alloc::vec::Vec<u8> {
        use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
        use justrdp_pdu::x224::{DataTransfer, DATA_TRANSFER_HEADER_SIZE};
        let inner = DATA_TRANSFER_HEADER_SIZE + pdu.size();
        let total = TPKT_HEADER_SIZE + inner;
        let mut buf = alloc::vec![0u8; total];
        let mut cursor = justrdp_core::WriteCursor::new(&mut buf);
        TpktHeader::try_for_payload(inner)
            .unwrap()
            .encode(&mut cursor)
            .unwrap();
        DataTransfer.encode(&mut cursor).unwrap();
        pdu.encode(&mut cursor).unwrap();
        buf
    }

    /// Drive an acceptor through Phase 1-4 and into ChannelConnection
    /// (WaitErectDomainRequest sub-phase) with the given list of static
    /// channel names.
    fn drive_to_channel_connection(channels: &[&str]) -> ServerAcceptor {
        let mut acc = drive_to_wait_mcs();
        let client_blocks = build_client_gcc_blocks(channels);
        let ci_bytes = build_mcs_connect_initial_bytes(&client_blocks);
        let mut out = WriteBuf::new();
        acc.step(&ci_bytes, &mut out).unwrap(); // -> SendMcsConnectResponse
        acc.step(&[], &mut out).unwrap(); // -> ChannelConnection
        assert_eq!(acc.state(), &ServerAcceptorState::ChannelConnection);
        acc
    }

    #[test]
    fn channel_connection_full_handshake_no_static_channels() {
        let mut acc = drive_to_channel_connection(&[]);
        let mut out = WriteBuf::new();

        // 1) Client sends Erect Domain Request (no response).
        let edr = ErectDomainRequest {
            sub_height: 0,
            sub_interval: 0,
        };
        let edr_bytes = build_slow_path(&edr);
        acc.step(&edr_bytes, &mut out).unwrap();
        assert!(out.is_empty());

        // 2) Client sends Attach User Request -> server responds with
        //    Attach User Confirm.
        let aur_bytes = build_slow_path(&AttachUserRequest);
        acc.step(&aur_bytes, &mut out).unwrap();
        let written = acc.step(&[], &mut out).unwrap();
        assert!(written.size > 0);
        // Decode the AttachUserConfirm we emitted.
        let mut c = ReadCursor::new(&out.as_slice()[..written.size]);
        let _ = TpktHeader::decode(&mut c).unwrap();
        let _ = DataTransfer::decode(&mut c).unwrap();
        let confirm = AttachUserConfirm::decode(&mut c).unwrap();
        assert_eq!(confirm.result, 0);
        let user_id = confirm.initiator.unwrap();
        assert_eq!(user_id, acc.user_channel_id());
        // No static channels + no message channel -> only [user, io] to join.
        assert_eq!(acc.channels_to_join.len(), 2);

        // 3) Channel join loop: user channel first.
        for &chid in &[user_id, crate::mcs::IO_CHANNEL_ID] {
            let req = ChannelJoinRequest {
                initiator: user_id,
                channel_id: chid,
            };
            let req_bytes = build_slow_path(&req);
            acc.step(&req_bytes, &mut out).unwrap();
            let written = acc.step(&[], &mut out).unwrap();
            let mut c = ReadCursor::new(&out.as_slice()[..written.size]);
            let _ = TpktHeader::decode(&mut c).unwrap();
            let _ = DataTransfer::decode(&mut c).unwrap();
            let confirm = ChannelJoinConfirm::decode(&mut c).unwrap();
            assert_eq!(confirm.result, 0);
            assert_eq!(confirm.initiator, user_id);
            assert_eq!(confirm.requested, chid);
            assert_eq!(confirm.channel_id, Some(chid));
        }

        // 4) After all joins, the next step transitions out of
        //    ChannelConnection.
        acc.step(&[], &mut out).unwrap();
        assert_eq!(acc.state(), &ServerAcceptorState::WaitClientInfo);
    }

    #[test]
    fn channel_connection_with_static_channels_and_message_channel() {
        // Client requests message channel + 2 static VCs.
        use justrdp_pdu::gcc::client::{
            ClientCoreData, ClientMessageChannelData, ClientNetworkData, ClientSecurityData,
            ChannelDef,
        };
        let core = ClientCoreData::new(1024, 768);
        let security = ClientSecurityData::new();
        let net = ClientNetworkData {
            channels: alloc::vec![ChannelDef::new("rdpdr", 0), ChannelDef::new("snd", 0)],
        };
        let msg = ClientMessageChannelData { flags: 0 };
        let mut buf = alloc::vec![0u8; core.size() + security.size() + net.size() + msg.size()];
        {
            let mut c = justrdp_core::WriteCursor::new(&mut buf);
            core.encode(&mut c).unwrap();
            security.encode(&mut c).unwrap();
            net.encode(&mut c).unwrap();
            msg.encode(&mut c).unwrap();
        }
        let ci_bytes = build_mcs_connect_initial_bytes(&buf);
        let cfg = AcceptorConfig::builder()
            .support_message_channel(true)
            .build();
        let mut acc = ServerAcceptor::new(cfg);
        let nego = NegotiationRequest::new(SecurityProtocol::HYBRID);
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        acc.step(&[], &mut out).unwrap(); // CC
        acc.step(&[], &mut out).unwrap(); // TLS
        acc.step(&[], &mut out).unwrap(); // CredSSP
        acc.step(&ci_bytes, &mut out).unwrap();
        acc.step(&[], &mut out).unwrap(); // -> ChannelConnection

        // Phase 5
        acc.step(&build_slow_path(&ErectDomainRequest { sub_height: 0, sub_interval: 0 }), &mut out).unwrap();
        acc.step(&build_slow_path(&AttachUserRequest), &mut out).unwrap();
        acc.step(&[], &mut out).unwrap(); // AttachUserConfirm
        let user_id = acc.user_channel_id();

        // user, io, message, static1, static2 = 5 channels
        assert_eq!(acc.channels_to_join.len(), 5);

        // Join all 5 channels in sequence.
        let to_join = acc.channels_to_join.clone();
        for chid in to_join {
            let req = ChannelJoinRequest {
                initiator: user_id,
                channel_id: chid,
            };
            acc.step(&build_slow_path(&req), &mut out).unwrap();
            acc.step(&[], &mut out).unwrap();
        }
        // Done -> next step transitions to WaitClientInfo.
        acc.step(&[], &mut out).unwrap();
        assert_eq!(acc.state(), &ServerAcceptorState::WaitClientInfo);
    }

    #[test]
    fn channel_join_rejects_unallocated_channel_id() {
        let mut acc = drive_to_channel_connection(&[]);
        let mut out = WriteBuf::new();
        acc.step(&build_slow_path(&ErectDomainRequest { sub_height: 0, sub_interval: 0 }), &mut out).unwrap();
        acc.step(&build_slow_path(&AttachUserRequest), &mut out).unwrap();
        acc.step(&[], &mut out).unwrap();
        let user_id = acc.user_channel_id();
        // Bogus channel ID that wasn't allocated.
        let req = ChannelJoinRequest {
            initiator: user_id,
            channel_id: 0xBEEF,
        };
        let err = acc.step(&build_slow_path(&req), &mut out).unwrap_err();
        assert!(alloc::format!("{err}").contains("unallocated"));
    }

    #[test]
    fn channel_join_rejects_wrong_initiator() {
        let mut acc = drive_to_channel_connection(&[]);
        let mut out = WriteBuf::new();
        acc.step(&build_slow_path(&ErectDomainRequest { sub_height: 0, sub_interval: 0 }), &mut out).unwrap();
        acc.step(&build_slow_path(&AttachUserRequest), &mut out).unwrap();
        acc.step(&[], &mut out).unwrap();
        let user_id = acc.user_channel_id();
        // Spoofed initiator (not the allocated user channel).
        let req = ChannelJoinRequest {
            initiator: user_id.wrapping_add(7),
            channel_id: user_id,
        };
        let err = acc.step(&build_slow_path(&req), &mut out).unwrap_err();
        assert!(alloc::format!("{err}").contains("initiator"));
    }

    #[test]
    fn channel_join_rejects_duplicate_join() {
        // Regression: previously a client could send Join(user_id) twice;
        // both would pass `contains()` and `channel_join_index` would
        // advance past the I/O channel without ever joining it.
        let mut acc = drive_to_channel_connection(&[]);
        let mut out = WriteBuf::new();
        acc.step(
            &build_slow_path(&ErectDomainRequest { sub_height: 0, sub_interval: 0 }),
            &mut out,
        )
        .unwrap();
        acc.step(&build_slow_path(&AttachUserRequest), &mut out).unwrap();
        acc.step(&[], &mut out).unwrap();
        let user_id = acc.user_channel_id();

        // First join is fine.
        let req = ChannelJoinRequest {
            initiator: user_id,
            channel_id: user_id,
        };
        acc.step(&build_slow_path(&req), &mut out).unwrap();
        acc.step(&[], &mut out).unwrap();

        // Second join of the SAME channel is rejected as out-of-order
        // (the next expected channel is the I/O channel, not user_id).
        let dup = ChannelJoinRequest {
            initiator: user_id,
            channel_id: user_id,
        };
        let err = acc.step(&build_slow_path(&dup), &mut out).unwrap_err();
        let msg = alloc::format!("{err}");
        assert!(
            msg.contains("out-of-order") || msg.contains("duplicate"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn channel_join_rejects_out_of_order() {
        // channels_to_join is [user, io]. Sending join(io) first
        // (skipping the user channel) must be rejected.
        let mut acc = drive_to_channel_connection(&[]);
        let mut out = WriteBuf::new();
        acc.step(
            &build_slow_path(&ErectDomainRequest { sub_height: 0, sub_interval: 0 }),
            &mut out,
        )
        .unwrap();
        acc.step(&build_slow_path(&AttachUserRequest), &mut out).unwrap();
        acc.step(&[], &mut out).unwrap();
        let user_id = acc.user_channel_id();

        let req = ChannelJoinRequest {
            initiator: user_id,
            channel_id: crate::mcs::IO_CHANNEL_ID,
        };
        let err = acc.step(&build_slow_path(&req), &mut out).unwrap_err();
        assert!(alloc::format!("{err}").contains("out-of-order"));
    }

    #[test]
    fn user_channel_id_starts_at_or_above_0x03ef() {
        let mut acc = drive_to_channel_connection(&[]);
        let mut out = WriteBuf::new();
        acc.step(&build_slow_path(&ErectDomainRequest { sub_height: 0, sub_interval: 0 }), &mut out).unwrap();
        acc.step(&build_slow_path(&AttachUserRequest), &mut out).unwrap();
        acc.step(&[], &mut out).unwrap();
        // Even with no static channels and no message channel, the user
        // channel ID must be >= 0x03EF (1007) per Windows convention.
        assert!(acc.user_channel_id() >= 0x03EF);
    }

    #[test]
    fn make_acceptance_result_reflects_negotiation() {
        let nego = NegotiationRequest::new(SecurityProtocol::HYBRID);
        let cr = ConnectionRequest::new(Some(nego));
        let cr_bytes = build_cr_bytes(&cr);

        let mut acc = ServerAcceptor::new(AcceptorConfig::default());
        let mut out = WriteBuf::new();
        acc.step(&cr_bytes, &mut out).unwrap();
        let _ = acc.step(&[], &mut out).unwrap();
        let result = acc.make_acceptance_result();
        assert_eq!(result.selected_protocol, SecurityProtocol::HYBRID);
        assert!(result
            .server_nego_flags
            .contains(NegotiationResponseFlags::EXTENDED_CLIENT_DATA));
    }
}
