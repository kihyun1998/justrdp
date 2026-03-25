#![forbid(unsafe_code)]

//! Connection result types.

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_pdu::rdp::capabilities::CapabilitySet;
use justrdp_pdu::x224::SecurityProtocol;

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
#[derive(Debug, Clone)]
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
}
