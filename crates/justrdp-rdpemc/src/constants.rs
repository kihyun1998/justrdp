//! Wire constants from MS-RDPEMC v16.0.
//!
//! Values come directly from the spec; the source section is noted
//! next to each constant.

/// Static virtual channel name on which MS-RDPEMC runs, padded to the
/// 8-byte CHANNEL_DEF wire representation (MS-RDPBCGR §2.2.1.3.4.1).
///
/// The channel is a **static** SVC, not a DVC — MS-RDPEMC does not use
/// DRDYNVC despite its "virtual channel extension" name (MS-RDPEMC §2.1).
pub const ENCOMSP_CHANNEL_NAME: [u8; 8] = *b"encomsp\0";

/// Size of the common [`crate::pdu::OrderHeader`] in bytes (MS-RDPEMC §2.2.1).
pub const ORDER_HDR_SIZE: usize = 4;

/// Maximum `cchString` value allowed in a [`crate::pdu::UnicodeString`]
/// (MS-RDPEMC §2.2.2). Any value above this is a protocol violation.
pub const MAX_UNICODE_STRING_CCH: u16 = 1024;

/// Message type values from MS-RDPEMC §2.2.1.
pub mod odtype {
    /// `ODTYPE_FILTER_STATE_UPDATED` (§2.2.3.1).
    pub const FILTER_STATE_UPDATED: u16 = 0x0001;
    /// `ODTYPE_APP_REMOVED` (§2.2.3.3).
    pub const APP_REMOVED: u16 = 0x0002;
    /// `ODTYPE_APP_CREATED` (§2.2.3.2).
    pub const APP_CREATED: u16 = 0x0003;
    /// `ODTYPE_WND_REMOVED` (§2.2.3.5).
    pub const WND_REMOVED: u16 = 0x0004;
    /// `ODTYPE_WND_CREATED` (§2.2.3.4).
    pub const WND_CREATED: u16 = 0x0005;
    /// `ODTYPE_WND_SHOW` (§2.2.3.6).
    pub const WND_SHOW: u16 = 0x0006;
    /// `ODTYPE_PARTICIPANT_REMOVED` (§2.2.4.2).
    pub const PARTICIPANT_REMOVED: u16 = 0x0007;
    /// `ODTYPE_PARTICIPANT_CREATED` (§2.2.4.1).
    pub const PARTICIPANT_CREATED: u16 = 0x0008;
    /// `ODTYPE_PARTICIPANT_CTRL_CHANGED` (§2.2.4.3).
    pub const PARTICIPANT_CTRL_CHANGED: u16 = 0x0009;
    /// `ODTYPE_GRAPHICS_STREAM_PAUSED` (§2.2.5.1).
    pub const GRAPHICS_STREAM_PAUSED: u16 = 0x000A;
    /// `ODTYPE_GRAPHICS_STREAM_RESUMED` (§2.2.5.2).
    pub const GRAPHICS_STREAM_RESUMED: u16 = 0x000B;
    /// `ODTYPE_WND_RGN_UPDATE` (§2.2.3.7).
    pub const WND_RGN_UPDATE: u16 = 0x000C;
    /// `ODTYPE_PARTICIPANT_CTRL_CHANGE_RESPONSE` (§2.2.4.4).
    pub const PARTICIPANT_CTRL_CHANGE_RESPONSE: u16 = 0x000D;
}

/// Flag bit constants used across multiple PDU bodies.
pub mod flags {
    // ── OD_FILTER_STATE_UPDATED.Flags (§2.2.3.1) ─────────────────────

    /// `FILTER_ENABLED` — filter is active.
    pub const FILTER_ENABLED: u8 = 0x01;

    // ── OD_APP_CREATED.Flags (§2.2.3.2) ──────────────────────────────

    /// `APPLICATION_SHARED` — application is currently shared.
    pub const APPLICATION_SHARED: u16 = 0x0001;

    // ── OD_WND_CREATED.Flags (§2.2.3.4) ──────────────────────────────

    /// `WINDOW_SHARED` — window is currently shared.
    pub const WINDOW_SHARED: u16 = 0x0001;

    // ── OD_PARTICIPANT_CREATED.Flags (§2.2.4.1) ──────────────────────

    /// `MAY_VIEW` — participant may view the shared desktop.
    pub const MAY_VIEW: u16 = 0x0001;
    /// `MAY_INTERACT` — participant may interact with the shared desktop.
    pub const MAY_INTERACT: u16 = 0x0002;
    /// `IS_PARTICIPANT` — this PDU describes the receiving participant itself.
    ///
    /// Unicast only, never broadcast (MS-RDPEMC Appendix A <18>).
    pub const IS_PARTICIPANT: u16 = 0x0004;

    // ── OD_PARTICIPANT_CTRL_CHANGE.Flags (§2.2.4.3) ──────────────────

    /// `REQUEST_VIEW` — requesting view permission.
    pub const REQUEST_VIEW: u16 = 0x0001;
    /// `REQUEST_INTERACT` — requesting interact permission.
    pub const REQUEST_INTERACT: u16 = 0x0002;
    /// `ALLOW_CONTROL_REQUESTS` — requesting "allow control request" mode.
    ///
    /// Windows sharing managers neither send nor interpret this flag
    /// (MS-RDPEMC Appendix A <30>), but it is defined for completeness.
    pub const ALLOW_CONTROL_REQUESTS: u16 = 0x0008;
}

/// `DiscType` enumeration for [`crate::pdu::OdParticipantRemoved`]
/// (MS-RDPEMC §2.2.4.2). Windows receivers do not parse these values
/// (Appendix A <21>); they are informational.
pub mod participant_disconnect_reason {
    /// `PARTICIPANT_DISCONNECT_REASON_APP` — disconnect initiated by host.
    pub const APP: u32 = 0x0000_0000;
    /// `PARTICIPANT_DISCONNECT_REASON_CLI` — disconnect initiated by participant.
    pub const CLI: u32 = 0x0000_0002;
}
