#![forbid(unsafe_code)]

//! Server acceptor state machine implementation.

use justrdp_core::{Decode, PduHint, ReadCursor, WriteBuf};

use justrdp_pdu::tpkt::{TpktHeader, TpktHint};
use justrdp_pdu::x224::{
    ConnectionConfirm, ConnectionRequest, ConnectionRequestData, NegotiationFailure,
    NegotiationFailureCode, NegotiationRequestFlags, NegotiationResponse,
    NegotiationResponseFlags, SecurityProtocol,
};

use crate::config::AcceptorConfig;
use crate::encode_helpers::encode_connection_confirm;
use crate::error::{AcceptorError, AcceptorErrorKind, AcceptorResult};
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
        }
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
            ServerAcceptorState::ChannelConnection => Some(&TPKT_HINT),
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
            // Later commits will fill these in.
            ServerAcceptorState::TlsAccept
            | ServerAcceptorState::CredsspAccept
            | ServerAcceptorState::WaitMcsConnectInitial
            | ServerAcceptorState::SendMcsConnectResponse
            | ServerAcceptorState::ChannelConnection
            | ServerAcceptorState::WaitClientInfo
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
