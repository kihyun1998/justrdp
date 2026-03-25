#![forbid(unsafe_code)]

//! Client connector state machine states.

/// State of the RDP client connection sequence.
///
/// Convention:
/// - `Send*` states produce output (caller provides empty input `&[]`)
/// - `Wait*` states expect server PDU input
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientConnectorState {
    // ── Phase 1: Connection Initiation ──
    /// Send X.224 Connection Request (no input needed).
    ConnectionInitiation,
    /// Wait for X.224 Connection Confirm from server.
    ConnectionInitiationWaitConfirm,

    // ── Phase 2: Security Upgrade (external) ──
    /// Caller performs TLS handshake, then signals completion.
    SecurityUpgrade,

    // ── Phase 3: NLA/CredSSP (external) ──
    /// Caller performs CredSSP/NLA, then signals completion.
    CredSsp,

    // ── Phase 4: Basic Settings Exchange ──
    /// Send MCS Connect Initial with GCC client data.
    BasicSettingsExchangeSendInitial,
    /// Wait for MCS Connect Response with GCC server data.
    BasicSettingsExchangeWaitResponse,

    // ── Phase 5: Channel Connection ──
    /// Send Erect Domain Request.
    ChannelConnectionSendErectDomain,
    /// Send Attach User Request.
    ChannelConnectionSendAttachUser,
    /// Wait for Attach User Confirm.
    ChannelConnectionWaitAttachConfirm,
    /// Send Channel Join Request for the next channel.
    ChannelConnectionSendJoinRequest,
    /// Wait for Channel Join Confirm.
    ChannelConnectionWaitJoinConfirm,

    // ── Phase 7: Secure Settings Exchange ──
    /// Send Client Info PDU.
    SecureSettingsExchange,

    // ── Phase 9: Licensing ──
    /// Wait for licensing PDU from server.
    LicensingWait,

    // ── Phase 11: Capabilities Exchange ──
    /// Wait for Demand Active PDU from server.
    CapabilitiesWaitDemandActive,
    /// Send Confirm Active PDU.
    CapabilitiesSendConfirmActive,

    // ── Phase 12: Connection Finalization ──
    /// Send Synchronize PDU.
    FinalizationSendSynchronize,
    /// Send Control(Cooperate) PDU.
    FinalizationSendCooperate,
    /// Send Control(RequestControl) PDU.
    FinalizationSendRequestControl,
    /// Send Font List PDU.
    FinalizationSendFontList,
    /// Wait for server Synchronize PDU.
    FinalizationWaitSynchronize,
    /// Wait for server Control(Cooperate) PDU.
    FinalizationWaitCooperate,
    /// Wait for server Control(GrantedControl) PDU.
    FinalizationWaitGrantedControl,
    /// Wait for server Font Map PDU.
    FinalizationWaitFontMap,

    // ── Terminal ──
    /// Connection established successfully.
    Connected,
}

impl ClientConnectorState {
    /// Returns a human-readable name for this state.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ConnectionInitiation => "ConnectionInitiation",
            Self::ConnectionInitiationWaitConfirm => "ConnectionInitiationWaitConfirm",
            Self::SecurityUpgrade => "SecurityUpgrade",
            Self::CredSsp => "CredSsp",
            Self::BasicSettingsExchangeSendInitial => "BasicSettingsExchangeSendInitial",
            Self::BasicSettingsExchangeWaitResponse => "BasicSettingsExchangeWaitResponse",
            Self::ChannelConnectionSendErectDomain => "ChannelConnectionSendErectDomain",
            Self::ChannelConnectionSendAttachUser => "ChannelConnectionSendAttachUser",
            Self::ChannelConnectionWaitAttachConfirm => "ChannelConnectionWaitAttachConfirm",
            Self::ChannelConnectionSendJoinRequest => "ChannelConnectionSendJoinRequest",
            Self::ChannelConnectionWaitJoinConfirm => "ChannelConnectionWaitJoinConfirm",
            Self::SecureSettingsExchange => "SecureSettingsExchange",
            Self::LicensingWait => "LicensingWait",
            Self::CapabilitiesWaitDemandActive => "CapabilitiesWaitDemandActive",
            Self::CapabilitiesSendConfirmActive => "CapabilitiesSendConfirmActive",
            Self::FinalizationSendSynchronize => "FinalizationSendSynchronize",
            Self::FinalizationSendCooperate => "FinalizationSendCooperate",
            Self::FinalizationSendRequestControl => "FinalizationSendRequestControl",
            Self::FinalizationSendFontList => "FinalizationSendFontList",
            Self::FinalizationWaitSynchronize => "FinalizationWaitSynchronize",
            Self::FinalizationWaitCooperate => "FinalizationWaitCooperate",
            Self::FinalizationWaitGrantedControl => "FinalizationWaitGrantedControl",
            Self::FinalizationWaitFontMap => "FinalizationWaitFontMap",
            Self::Connected => "Connected",
        }
    }

    /// Whether this is a send state (connector produces output, no input needed).
    pub fn is_send_state(&self) -> bool {
        matches!(
            self,
            Self::ConnectionInitiation
                | Self::SecurityUpgrade
                | Self::CredSsp
                | Self::BasicSettingsExchangeSendInitial
                | Self::ChannelConnectionSendErectDomain
                | Self::ChannelConnectionSendAttachUser
                | Self::ChannelConnectionSendJoinRequest
                | Self::SecureSettingsExchange
                | Self::CapabilitiesSendConfirmActive
                | Self::FinalizationSendSynchronize
                | Self::FinalizationSendCooperate
                | Self::FinalizationSendRequestControl
                | Self::FinalizationSendFontList
        )
    }
}
