#![forbid(unsafe_code)]

//! Acceptance result types.

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_pdu::rdp::capabilities::CapabilitySet;
use justrdp_pdu::rdp::client_info::ClientInfoPdu;
use justrdp_pdu::x224::{NegotiationRequestFlags, NegotiationResponseFlags, SecurityProtocol};

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

/// Information captured from the client's X.224 Connection Request.
///
/// Stored on the acceptor while it advances through the connection sequence
/// so that later phases (e.g., MCS Connect Response, Demand Active) can
/// honour client-requested behaviour. Also available to the caller via
/// `ServerAcceptor::client_request()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRequestInfo {
    /// Cookie from `Cookie: mstshash=...\r\n`, if present.
    pub cookie: Option<String>,
    /// Routing token from `Cookie: msts=...\r\n`, if present.
    pub routing_token: Option<Vec<u8>>,
    /// Bitmask of `requestedProtocols` from `RDP_NEG_REQ`. Defaults to
    /// `PROTOCOL_RDP` (0) when no `RDP_NEG_REQ` is present in the CR
    /// (legacy RDP 4.x/5.0 client).
    pub requested_protocols: SecurityProtocol,
    /// Flags from `RDP_NEG_REQ`. Defaults to empty.
    pub request_flags: NegotiationRequestFlags,
    /// Whether `RDP_NEG_REQ` was present in the CR. When `false` the server
    /// MUST send a Connection Confirm with no `rdpNegData` (legacy path).
    pub had_negotiation_request: bool,
}

impl ClientRequestInfo {
    #[allow(dead_code)] // Used by tests and later commits.
    pub(crate) fn legacy() -> Self {
        Self {
            cookie: None,
            routing_token: None,
            requested_protocols: SecurityProtocol::RDP,
            request_flags: NegotiationRequestFlags::NONE,
            had_negotiation_request: false,
        }
    }
}

/// Result of a successful RDP server connection acceptance.
///
/// Filled in incrementally by later phases (MCS, capabilities, etc.).
/// Phase 1 only populates `selected_protocol` and `server_nego_flags`;
/// the remaining fields are left at their default values until the
/// corresponding phase runs.
///
/// The terminal `Accepted { result }` hands ownership of this struct to
/// the caller, so it must carry *everything* the post-connection
/// session driver needs (negotiated caps, credentials, channel IDs) --
/// callers who dispose of the `ServerAcceptor` after the handshake
/// cannot call accessors on it.
///
/// **Credential hygiene.** The `client_info` field embeds the parsed
/// `ClientInfoPdu`, which carries the user's plaintext password.
/// `ClientInfoPdu::Drop` zeroes the password on drop, but:
/// - **`Clone`** allocates a second heap buffer with the plaintext
///   password. Both copies zero independently when dropped, but they
///   coexist between the clone and the first drop. Prefer moving the
///   `AcceptanceResult` rather than cloning it.
/// - **`Debug`** prints the raw struct fields; redact the password
///   before logging (or call
///   [`take_client_info`](Self::take_client_info) to extract the PDU
///   through a move so subsequent `Debug`/`Clone` sees `None`).
/// - The credential can be extracted (and removed from the result)
///   via [`take_client_info`](Self::take_client_info).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptanceResult {
    /// Security protocol the server selected in `RDP_NEG_RSP`.
    pub selected_protocol: SecurityProtocol,
    /// Flags the server placed in `RDP_NEG_RSP`.
    pub server_nego_flags: NegotiationResponseFlags,
    /// Information captured from the client's CR.
    pub client_request: ClientRequestInfo,
    /// MCS I/O channel ID assigned by the server (filled in Phase 4).
    pub io_channel_id: u16,
    /// MCS user channel ID assigned to the joined user (filled in Phase 5).
    pub user_channel_id: u16,
    /// MCS message channel ID, if one was allocated in Phase 4.
    pub message_channel_id: Option<u16>,
    /// Share ID assigned by the server (filled in Phase 11).
    pub share_id: u32,
    /// Channel name to MCS channel ID mapping (filled in Phase 4).
    pub channel_ids: Vec<(String, u16)>,
    /// Capability sets the client returned in ConfirmActive (filled
    /// in Phase 11). Empty before the confirm arrives.
    pub client_capabilities: Vec<CapabilitySet>,
    /// Parsed Client Info PDU (filled in Phase 7). `None` if the
    /// connection terminated before the secure-settings exchange.
    /// The `ClientInfoPdu::Drop` impl zeroes the password on drop.
    pub client_info: Option<ClientInfoPdu>,
}

impl AcceptanceResult {
    /// Move the Client Info PDU out of the result, leaving `None`.
    ///
    /// Use this to isolate credential handling: the extracted PDU can be
    /// passed to a dedicated credential-validation routine and dropped
    /// (zero-on-drop) as soon as the validation completes, while the
    /// rest of the `AcceptanceResult` can be cloned / logged / shipped
    /// across threads without carrying a live password.
    pub fn take_client_info(&mut self) -> Option<ClientInfoPdu> {
        self.client_info.take()
    }

    #[allow(dead_code)] // Used by tests and later commits.
    pub(crate) fn new(client_request: ClientRequestInfo) -> Self {
        Self {
            selected_protocol: SecurityProtocol::RDP,
            server_nego_flags: NegotiationResponseFlags::NONE,
            client_request,
            io_channel_id: 0,
            user_channel_id: 0,
            message_channel_id: None,
            share_id: 0,
            channel_ids: Vec::new(),
            client_capabilities: Vec::new(),
            client_info: None,
        }
    }
}
