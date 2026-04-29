#![forbid(unsafe_code)]

//! Client connector state machine states.

use crate::result::ConnectionResult;

/// State of the RDP client connection sequence.
///
/// Follows MS-RDPBCGR 1.3.1.1 connection sequence phases.
///
/// Convention:
/// - `Send*` states produce output (caller provides empty input `&[]`)
/// - `Wait*` states expect server PDU input
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientConnectorState {
    // ── Phase 1: Connection Initiation ──
    /// Send X.224 Connection Request (no input needed).
    ConnectionInitiationSendRequest,
    /// Wait for X.224 Connection Confirm from server.
    ConnectionInitiationWaitConfirm,

    // ── Phase 2: Security Upgrade (external) ──
    /// Caller performs TLS handshake, then signals completion.
    EnhancedSecurityUpgrade,

    // ── Phase 3: NLA/CredSSP ──
    /// CredSSP SPNEGO negotiation tokens exchange.
    CredsspNegoTokens,
    /// CredSSP public key authentication.
    CredsspPubKeyAuth,
    /// CredSSP encrypted credentials transfer.
    CredsspCredentials,
    /// CredSSP early user authorization result (HYBRID_EX only).
    CredsspEarlyUserAuth,

    // ── Phase 3a: Azure AD Authentication (RDSAAD) ──
    /// Wait for server nonce JSON PDU.
    AadWaitServerNonce,
    /// Send authentication request with RDP Assertion (JWS).
    AadSendAuthRequest,
    /// Wait for authentication result from server.
    AadWaitAuthResult,

    // ── Phase 3b: RDSTLS (Remote Credential Guard) ──
    /// Send RDSTLS Capabilities to server.
    RdstlsSendCapabilities,
    /// Wait for server RDSTLS Capabilities.
    RdstlsWaitCapabilities,
    /// Send RDSTLS Authentication Request.
    RdstlsSendAuthRequest,
    /// Wait for RDSTLS Authentication Response.
    RdstlsWaitAuthResponse,

    // ── Phase 4: Basic Settings Exchange ──
    /// Send MCS Connect Initial with GCC client data.
    BasicSettingsExchangeSendInitial,
    /// Wait for MCS Connect Response with GCC server data.
    BasicSettingsExchangeWaitResponse,

    // ── Phase 5: Channel Connection ──
    /// Send Erect Domain Request.
    ChannelConnectionSendErectDomainRequest,
    /// Send Attach User Request.
    ChannelConnectionSendAttachUserRequest,
    /// Wait for Attach User Confirm.
    ChannelConnectionWaitAttachUserConfirm,
    /// Channel Join loop: send Join Request / wait Join Confirm for each channel.
    ChannelConnectionChannelJoin,

    // ── Phase 6: Security Commencement (Standard RDP Security only) ──
    /// Send Security Exchange PDU (encrypted client random) and derive session keys.
    SecurityCommencement,

    // ── Phase 7: Secure Settings Exchange ──
    /// Send Client Info PDU.
    SecureSettingsExchange,

    // ── Phase 8: Connect-Time Auto-Detection ──
    /// Optional server-initiated auto-detection (MS-RDPBCGR 1.3.1.1, phase 8).
    ConnectTimeAutoDetection,

    // ── Phase 9: Licensing ──
    /// License exchange with server (Valid Client shortcut or full negotiation).
    LicensingExchange,

    // ── Phase 10: Multitransport Bootstrapping ──
    /// Optional multitransport bootstrapping (MS-RDPBCGR 2.2.15.1).
    MultitransportBootstrapping,

    // ── Phase 11: Capabilities Exchange ──
    /// Wait for Demand Active PDU from server.
    CapabilitiesExchangeWaitDemandActive,
    /// Send Confirm Active PDU.
    CapabilitiesExchangeSendConfirmActive,

    // ── Phase 12: Connection Finalization ──
    /// Send Synchronize PDU.
    ConnectionFinalizationSendSynchronize,
    /// Send Control(Cooperate) PDU.
    ConnectionFinalizationSendCooperate,
    /// Send Control(RequestControl) PDU.
    ConnectionFinalizationSendRequestControl,
    /// Send Persistent Key List PDU (bitmap cache keys).
    ConnectionFinalizationSendPersistentKeyList,
    /// Send Font List PDU.
    ConnectionFinalizationSendFontList,
    /// Wait for server finalization PDUs. Per MS-RDPBCGR §2.2.1.22 the
    /// Server Font Map PDU is the **last** PDU of the connection sequence,
    /// so it is the sole trigger for `Connected`. The preceding three PDUs
    /// (Synchronize §2.2.1.19, Control-Cooperate §2.2.1.20, Control-
    /// GrantedControl §2.2.1.21) are accepted in any order and silently
    /// consumed — the spec does not constrain the client receive order, and
    /// a strict per-PDU state chain wedges when servers interleave
    /// SaveSessionInfo / MonitorLayout / out-of-order frames.
    ConnectionFinalizationWaitFontMap,

    // ── Terminal ──
    /// Connection established successfully.
    Connected {
        /// Connection result with channel IDs, server capabilities, etc.
        result: ConnectionResult,
    },
}

impl ClientConnectorState {
    /// Returns a human-readable name for this state.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ConnectionInitiationSendRequest => "ConnectionInitiationSendRequest",
            Self::ConnectionInitiationWaitConfirm => "ConnectionInitiationWaitConfirm",
            Self::EnhancedSecurityUpgrade => "EnhancedSecurityUpgrade",
            Self::CredsspNegoTokens => "CredsspNegoTokens",
            Self::CredsspPubKeyAuth => "CredsspPubKeyAuth",
            Self::CredsspCredentials => "CredsspCredentials",
            Self::CredsspEarlyUserAuth => "CredsspEarlyUserAuth",
            Self::AadWaitServerNonce => "AadWaitServerNonce",
            Self::AadSendAuthRequest => "AadSendAuthRequest",
            Self::AadWaitAuthResult => "AadWaitAuthResult",
            Self::RdstlsSendCapabilities => "RdstlsSendCapabilities",
            Self::RdstlsWaitCapabilities => "RdstlsWaitCapabilities",
            Self::RdstlsSendAuthRequest => "RdstlsSendAuthRequest",
            Self::RdstlsWaitAuthResponse => "RdstlsWaitAuthResponse",
            Self::BasicSettingsExchangeSendInitial => "BasicSettingsExchangeSendInitial",
            Self::BasicSettingsExchangeWaitResponse => "BasicSettingsExchangeWaitResponse",
            Self::ChannelConnectionSendErectDomainRequest => "ChannelConnectionSendErectDomainRequest",
            Self::ChannelConnectionSendAttachUserRequest => "ChannelConnectionSendAttachUserRequest",
            Self::ChannelConnectionWaitAttachUserConfirm => "ChannelConnectionWaitAttachUserConfirm",
            Self::ChannelConnectionChannelJoin => "ChannelConnectionChannelJoin",
            Self::SecurityCommencement => "SecurityCommencement",
            Self::SecureSettingsExchange => "SecureSettingsExchange",
            Self::ConnectTimeAutoDetection => "ConnectTimeAutoDetection",
            Self::LicensingExchange => "LicensingExchange",
            Self::MultitransportBootstrapping => "MultitransportBootstrapping",
            Self::CapabilitiesExchangeWaitDemandActive => "CapabilitiesExchangeWaitDemandActive",
            Self::CapabilitiesExchangeSendConfirmActive => "CapabilitiesExchangeSendConfirmActive",
            Self::ConnectionFinalizationSendSynchronize => "ConnectionFinalizationSendSynchronize",
            Self::ConnectionFinalizationSendCooperate => "ConnectionFinalizationSendCooperate",
            Self::ConnectionFinalizationSendRequestControl => "ConnectionFinalizationSendRequestControl",
            Self::ConnectionFinalizationSendPersistentKeyList => "ConnectionFinalizationSendPersistentKeyList",
            Self::ConnectionFinalizationSendFontList => "ConnectionFinalizationSendFontList",
            Self::ConnectionFinalizationWaitFontMap => "ConnectionFinalizationWaitFontMap",
            Self::Connected { .. } => "Connected",
        }
    }

    /// Whether this is a send state (connector produces output, no input needed).
    pub fn is_send_state(&self) -> bool {
        matches!(
            self,
            Self::ConnectionInitiationSendRequest
                | Self::EnhancedSecurityUpgrade
                | Self::CredsspNegoTokens
                | Self::CredsspPubKeyAuth
                | Self::CredsspCredentials
                | Self::CredsspEarlyUserAuth
                | Self::AadSendAuthRequest
                | Self::RdstlsSendCapabilities
                | Self::RdstlsSendAuthRequest
                | Self::BasicSettingsExchangeSendInitial
                | Self::ChannelConnectionSendErectDomainRequest
                | Self::ChannelConnectionSendAttachUserRequest
                // ChannelConnectionChannelJoin excluded: it alternates send/wait,
                // handled by channel_join_sending flag in next_pdu_hint()
                | Self::SecurityCommencement
                | Self::SecureSettingsExchange
                // MultitransportBootstrapping was a send state when stubbed
                // (it produced no output and transitioned immediately). The
                // real implementation needs to wait for a server PDU on the
                // MCS message channel, so it must NOT be in `is_send_state`.
                | Self::CapabilitiesExchangeSendConfirmActive
                | Self::ConnectionFinalizationSendSynchronize
                | Self::ConnectionFinalizationSendCooperate
                | Self::ConnectionFinalizationSendRequestControl
                | Self::ConnectionFinalizationSendPersistentKeyList
                | Self::ConnectionFinalizationSendFontList
        )
    }

    /// Whether this is the terminal Connected state.
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }
}
