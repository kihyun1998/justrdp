#![forbid(unsafe_code)]

//! Connection result types.

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_pdu::rdp::capabilities::CapabilitySet;
use justrdp_pdu::rdp::finalization::MonitorLayoutEntry;
use justrdp_pdu::x224::SecurityProtocol;

use crate::config::ArcCookie;

/// Number of bytes written to the output buffer by a `step()` call.
#[derive(Debug, Clone, Copy)]
pub struct Written {
    /// Bytes written to the output `WriteBuf`.
    pub size: usize,
}

impl Written {
    /// No bytes were written (e.g., for receive-only states).
    pub fn nothing() -> Self {
        Self { size: 0 }
    }

    /// A specific number of bytes were written.
    pub fn new(size: usize) -> Self {
        Self { size }
    }
}

/// Result of a successful RDP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionResult {
    /// MCS I/O channel ID (from ServerNetworkData).
    pub io_channel_id: u16,
    /// MCS user channel ID (from AttachUserConfirm).
    pub user_channel_id: u16,
    /// Share ID (from Demand Active PDU).
    pub share_id: u32,
    /// Server capability sets (from Demand Active PDU).
    pub server_capabilities: Vec<CapabilitySet>,
    /// Channel name to MCS channel ID mapping.
    pub channel_ids: Vec<(String, u16)>,
    /// Security protocol selected during negotiation.
    pub selected_protocol: SecurityProtocol,
    /// Session ID from the server (0 if not provided).
    pub session_id: u32,
    /// Server monitor layout received during capabilities exchange (MS-RDPBCGR 2.2.12.1).
    ///
    /// The server sends this optional PDU after the Demand Active PDU when the client
    /// set `SUPPORT_MONITOR_LAYOUT_PDU` in `earlyCapabilityFlags`. `None` if the server
    /// did not send a Monitor Layout PDU during the connection sequence.
    pub server_monitor_layout: Option<Vec<MonitorLayoutEntry>>,
    /// Server-issued Auto-Reconnect Cookie received during the connection sequence
    /// (MS-RDPBCGR 2.2.4.2).
    ///
    /// Most servers send the ARC cookie *after* the connection sequence completes,
    /// inside a Save Session Info PDU during the active session — extract those via
    /// `ActiveStageOutput::SaveSessionInfo` and `SaveSessionInfoData::arc_cookie()`.
    /// This field captures the rare case where the server sends it during the
    /// finalization phase. `None` if no cookie was received during the connection.
    pub server_arc_cookie: Option<ArcCookie>,
}
