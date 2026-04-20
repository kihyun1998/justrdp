#![forbid(unsafe_code)]

//! DRDYNVC static virtual channel processor -- MS-RDPEDYC 3.1
//!
//! `DrdynvcClient` implements `SvcProcessor` to handle the DRDYNVC SVC,
//! managing DVC capability negotiation, channel create/close, and data dispatch.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_bulk::zgfx::ZgfxDecompressor;
use justrdp_core::{AsAny, ReadCursor};
use justrdp_svc::{
    ChannelName, CompressionCondition, SvcMessage, SvcProcessor, SvcResult, DRDYNVC,
};

use crate::pdu::{
    self, DvcPdu, SoftSyncChannelList, CAPS_VERSION_3, CREATION_STATUS_OK,
    SOFT_SYNC_CHANNEL_LIST_PRESENT, SOFT_SYNC_TCP_FLUSHED,
};
use crate::reassembly::DvcReassembler;
use crate::{DvcError, DvcOutput, DvcProcessor, DvcResult};

/// Maximum DVC version we support.
const MAX_SUPPORTED_VERSION: u16 = CAPS_VERSION_3;

/// Maximum number of simultaneously open DVC channels.
const MAX_ACTIVE_CHANNELS: usize = 256;

/// HRESULT for failed channel creation (no registered processor).
/// MS-RDPEDYC 2.2.2.2: CreationStatus is HRESULT; E_FAIL (0x80004005) signals
/// no registered listener for the requested channel name.
const CREATION_STATUS_NO_LISTENER: i32 = -2147467259; // 0x80004005 = E_FAIL

/// Client-side DRDYNVC processor.
///
/// Implements `SvcProcessor` for the `drdynvc` static virtual channel.
/// Manages dynamic virtual channel lifecycle: capability negotiation,
/// channel creation/closing, and data routing to registered `DvcProcessor`s.
pub struct DrdynvcClient {
    /// Registered DVC processors, keyed by channel name.
    processors: BTreeMap<String, Box<dyn DvcProcessor>>,
    /// Active channels: channel_id → channel_name.
    active_channels: BTreeMap<u32, String>,
    /// Per-channel reassembly state.
    reassemblers: BTreeMap<u32, DvcReassembler>,
    /// Per-channel ZGFX Lite decompressors for compressed DVC data (v3).
    decompressors: BTreeMap<u32, ZgfxDecompressor>,
    /// Negotiated version (0 = not yet negotiated).
    negotiated_version: u16,

    // ── Multitransport / Soft-Sync routing (MS-RDPEDYC §3.1.5.3) ──
    //
    // Populated lazily by `notify_tunnels_ready` and the `SoftSyncRequest`
    // handler. Empty when multitransport is not in use, which is the
    // default while the connector still rejects `Initiate Multitransport
    // Request` with E_ABORT (Commit D).

    /// Tunnel types the caller has signalled as ready for use (e.g.
    /// after the RDPEMT `RDP_TUNNEL_CREATERESPONSE` has been received
    /// successfully). Indexed by `TUNNELTYPE_*` u32 value.
    available_tunnels: BTreeSet<u32>,
    /// Inbound routing decided at SoftSyncRequest time:
    /// `channel_id → tunnel_type` for DVCs the **server** will write
    /// over a multitransport tunnel. Channels not present here arrive
    /// over the DRDYNVC SVC.
    channel_to_tunnel: BTreeMap<u32, u32>,
    /// Tunnel types the **client** is currently writing DVC data over,
    /// snapshotted at SoftSyncResponse send time. A channel's outbound
    /// route is determined by looking up its `channel_to_tunnel` entry
    /// and confirming that tunnel type is in this set.
    outbound_tunnels: BTreeSet<u32>,
}

impl DrdynvcClient {
    /// Create a new DRDYNVC client processor.
    pub fn new() -> Self {
        Self {
            processors: BTreeMap::new(),
            active_channels: BTreeMap::new(),
            reassemblers: BTreeMap::new(),
            decompressors: BTreeMap::new(),
            negotiated_version: 0,
            available_tunnels: BTreeSet::new(),
            channel_to_tunnel: BTreeMap::new(),
            outbound_tunnels: BTreeSet::new(),
        }
    }

    /// Register a DVC processor.
    pub fn register(&mut self, processor: Box<dyn DvcProcessor>) {
        let name = String::from(processor.channel_name());
        self.processors.insert(name, processor);
    }

    /// Get the negotiated DVC version (0 if not yet negotiated).
    pub fn negotiated_version(&self) -> u16 {
        self.negotiated_version
    }

    // ──────────────────────────────────────────────────────────────────
    // Multitransport / Soft-Sync routing (MS-RDPEDYC §3.1.5.3)
    // ──────────────────────────────────────────────────────────────────

    /// Notify the DRDYNVC manager that one or more multitransport tunnels
    /// (`TUNNELTYPE_UDPFECR` / `TUNNELTYPE_UDPFECL`) are connected and
    /// ready for DVC routing. Must be called *before* the server sends
    /// `DYNVC_SOFT_SYNC_REQUEST`; otherwise the request will be answered
    /// silently (no Response → spec-compliant SVC fallback per §3.2.5.3.1).
    ///
    /// Idempotent: subsequent calls add to the available set.
    ///
    /// **Namespace caveat**: pass MS-RDPEDYC values
    /// ([`TUNNELTYPE_UDPFECR`](crate::pdu::TUNNELTYPE_UDPFECR) = 0x01,
    /// [`TUNNELTYPE_UDPFECL`](crate::pdu::TUNNELTYPE_UDPFECL) = 0x03),
    /// **not** MS-RDPBCGR `TRANSPORTTYPE_*` values (where UDPFECL is
    /// 0x04). UDPFECR happens to share value 0x01 in both namespaces;
    /// UDPFECL silently fails to match if the wrong namespace is used.
    pub fn notify_tunnels_ready(&mut self, tunnel_types: &[u32]) {
        for &t in tunnel_types {
            self.available_tunnels.insert(t);
        }
    }

    /// Look up the multitransport tunnel that the **server** uses to
    /// deliver inbound data for `channel_id`. `None` means the channel
    /// is still routed over the DRDYNVC SVC.
    pub fn inbound_tunnel_for(&self, channel_id: u32) -> Option<u32> {
        self.channel_to_tunnel.get(&channel_id).copied()
    }

    /// Look up the multitransport tunnel that the **client** must use
    /// to write outbound data for `channel_id`. Returns `None` for
    /// channels not Soft-Synced or for tunnels the client opted out of
    /// in its `SoftSyncResponse` (i.e. `outbound_tunnels` does not
    /// contain that tunnel type).
    pub fn outbound_tunnel_for(&self, channel_id: u32) -> Option<u32> {
        let tunnel = *self.channel_to_tunnel.get(&channel_id)?;
        if self.outbound_tunnels.contains(&tunnel) {
            Some(tunnel)
        } else {
            None
        }
    }

    /// Process a Soft-Sync Request (§2.2.5.1) and, if any of the
    /// requested tunnels are available, populate the inbound routing
    /// table and emit a Soft-Sync Response (§2.2.5.2) to be sent over
    /// the DRDYNVC SVC. Returns `Ok(vec![])` when no tunnels match
    /// (per §3.2.5.3.1, the absence of a Response keeps DVC traffic
    /// on the SVC, which is exactly what JustRDP wants in that case).
    ///
    /// Errors:
    /// - `DvcError::Protocol` if the same `channel_id` appears in more
    ///   than one channel list (MS-RDPEDYC §2.2.5.1.1: MUST NOT).
    fn handle_soft_sync_request(
        &mut self,
        flags: u16,
        channel_lists: Vec<SoftSyncChannelList>,
    ) -> DvcResult<Vec<SvcMessage>> {
        // Defensive: even though decode validates SOFT_SYNC_TCP_FLUSHED,
        // re-assert here so we never act on a malformed request that
        // somehow slipped through (e.g. via a future direct constructor).
        if flags & SOFT_SYNC_TCP_FLUSHED == 0 {
            return Err(DvcError::Protocol(String::from(
                "DYNVC_SOFT_SYNC_REQUEST without SOFT_SYNC_TCP_FLUSHED",
            )));
        }
        // §2.2.5.1: if the LIST_PRESENT bit is unset there must be no
        // channel lists (the decoder enforces this by tying it to
        // NumberOfTunnels==0; re-assert defensively here too).
        if flags & SOFT_SYNC_CHANNEL_LIST_PRESENT == 0 && !channel_lists.is_empty() {
            return Err(DvcError::Protocol(String::from(
                "DYNVC_SOFT_SYNC_REQUEST: channel lists present without SOFT_SYNC_CHANNEL_LIST_PRESENT",
            )));
        }

        // §2.2.5.1.1 MUST NOT: a channel_id may appear in at most one
        // SoftSyncChannelList. The decoder doesn't enforce this; do it
        // here before mutating any state.
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        for list in &channel_lists {
            for &id in &list.dvc_ids {
                if !seen.insert(id) {
                    return Err(DvcError::Protocol(alloc::format!(
                        "DYNVC_SOFT_SYNC_REQUEST: channel {} appears in multiple lists",
                        id,
                    )));
                }
            }
        }

        // Compute the intersection between what the server wants to use
        // and what the caller has signalled as ready. Channels assigned
        // to unsupported tunnels stay on the SVC.
        let mut activated_tunnels: BTreeSet<u32> = BTreeSet::new();
        for list in &channel_lists {
            if !self.available_tunnels.contains(&list.tunnel_type) {
                continue;
            }
            activated_tunnels.insert(list.tunnel_type);
            for &id in &list.dvc_ids {
                self.channel_to_tunnel.insert(id, list.tunnel_type);
            }
        }

        if activated_tunnels.is_empty() {
            // Spec-permitted no-op: not sending a Response keeps all DVC
            // traffic on the SVC (MS-RDPEDYC §3.2.5.3.1 "If the client
            // does not send a Soft-Sync Response PDU, then all DVC data
            // MUST be sent over the DRDYNVC SVC").
            return Ok(vec![]);
        }

        // Accumulate (don't replace) outbound routing — a future second
        // SoftSyncRequest must not silently drop channels assigned by an
        // earlier request from the outbound set, since `channel_to_tunnel`
        // also accumulates and the two views would otherwise diverge.
        // The Response PDU itself only advertises the *newly activated*
        // tunnels, which matches the spec's per-request semantics.
        self.outbound_tunnels.extend(activated_tunnels.iter().copied());
        let tunnels_to_switch: Vec<u32> = activated_tunnels.into_iter().collect();
        let response = pdu::encode_soft_sync_response(&tunnels_to_switch)
            .map_err(DvcError::Encode)?;
        Ok(vec![SvcMessage::new(response)])
    }

    /// Process a parsed DVC PDU and produce response SVC messages.
    fn process_pdu(&mut self, pdu: DvcPdu) -> DvcResult<Vec<SvcMessage>> {
        match pdu {
            DvcPdu::CapabilitiesRequest { version, .. } => {
                // Respond with the min of server version and our max supported.
                let negotiated = version.min(MAX_SUPPORTED_VERSION);
                self.negotiated_version = negotiated;
                let response = pdu::encode_caps_response(negotiated);
                Ok(vec![SvcMessage::new(response)])
            }

            DvcPdu::CreateRequest {
                channel_id,
                channel_name,
                priority: _,
            } => {
                if let Some(proc) = self.processors.get_mut(&channel_name) {
                    // Reject if too many channels are already open.
                    if !self.active_channels.contains_key(&channel_id)
                        && self.active_channels.len() >= MAX_ACTIVE_CHANNELS
                    {
                        return Ok(vec![SvcMessage::new(pdu::encode_create_response(
                            channel_id,
                            CREATION_STATUS_NO_LISTENER,
                        ))]);
                    }

                    // Close prior instance if this channel_id was already open.
                    if self.active_channels.contains_key(&channel_id) {
                        proc.close(channel_id);
                    }

                    // Accept the channel.
                    self.active_channels
                        .insert(channel_id, channel_name.clone());
                    self.reassemblers
                        .insert(channel_id, DvcReassembler::new());
                    // Create a per-channel decompressor for v3 compressed data.
                    if self.negotiated_version >= CAPS_VERSION_3 {
                        self.decompressors
                            .insert(channel_id, ZgfxDecompressor::new_lite());
                    }

                    let start_messages = proc.start(channel_id)?;

                    // Send CreateResponse(OK) first, then any start messages.
                    let mut responses = vec![SvcMessage::new(pdu::encode_create_response(
                        channel_id,
                        CREATION_STATUS_OK,
                    ))];

                    for msg in start_messages {
                        responses.push(SvcMessage::new(pdu::encode_data(channel_id, &msg.data)));
                    }

                    Ok(responses)
                } else {
                    // No listener — reject.
                    Ok(vec![SvcMessage::new(pdu::encode_create_response(
                        channel_id,
                        CREATION_STATUS_NO_LISTENER,
                    ))])
                }
            }

            DvcPdu::DataFirst {
                channel_id,
                total_length,
                data,
            } => self.handle_data_fragment(channel_id, Some(total_length), &data),

            DvcPdu::Data { channel_id, data } => {
                self.handle_data_fragment(channel_id, None, &data)
            }

            DvcPdu::DataFirstCompressed {
                channel_id,
                total_length,
                data,
            } => {
                let decompressed = self.decompress_chunk(channel_id, &data)?;
                self.handle_data_fragment(channel_id, Some(total_length), &decompressed)
            }

            DvcPdu::DataCompressed { channel_id, data } => {
                let decompressed = self.decompress_chunk(channel_id, &data)?;
                self.handle_data_fragment(channel_id, None, &decompressed)
            }

            DvcPdu::Close { channel_id } => {
                // Only echo close for channels we actually have open.
                if let Some(name) = self.active_channels.remove(&channel_id) {
                    if let Some(proc) = self.processors.get_mut(&name) {
                        proc.close(channel_id);
                    }
                    self.reassemblers.remove(&channel_id);
                    self.decompressors.remove(&channel_id);
                    Ok(vec![SvcMessage::new(pdu::encode_close(channel_id))])
                } else {
                    // Unknown channel — ignore per MS-RDPEDYC 3.1.5.1.4.
                    Ok(vec![])
                }
            }
            DvcPdu::SoftSyncRequest { flags, channel_lists } => {
                self.handle_soft_sync_request(flags, channel_lists)
            }
            DvcPdu::SoftSyncResponse { .. } => {
                // Server-bound PDU; receiving it on the client side is a
                // protocol violation.
                Err(DvcError::Protocol(String::from(
                    "unexpected DYNVC_SOFT_SYNC_RESPONSE on client",
                )))
            }
        }
    }

    /// Feed a data fragment into reassembly and dispatch if complete.
    fn handle_data_fragment(
        &mut self,
        channel_id: u32,
        total_length: Option<u32>,
        data: &[u8],
    ) -> DvcResult<Vec<SvcMessage>> {
        let reassembler = match self.reassemblers.get_mut(&channel_id) {
            Some(r) => r,
            None => return Ok(vec![]),
        };
        let complete = match total_length {
            Some(len) => reassembler.data_first(len, data)?,
            None => reassembler.data(data)?,
        };
        if let Some(payload) = complete {
            self.dispatch_data(channel_id, &payload)
        } else {
            Ok(vec![])
        }
    }

    /// Decompress a compressed DVC data chunk using the per-channel ZGFX Lite decompressor.
    fn decompress_chunk(&mut self, channel_id: u32, data: &[u8]) -> DvcResult<Vec<u8>> {
        let decompressor = self.decompressors.get_mut(&channel_id).ok_or_else(|| {
            DvcError::Protocol(String::from("compressed data on channel without decompressor"))
        })?;
        let mut output = Vec::new();
        decompressor
            .decompress(data, &mut output)
            .map_err(|e| DvcError::Protocol(alloc::format!("DVC decompression failed: {e:?}")))?;
        Ok(output)
    }

    /// Dispatch complete data to the registered processor.
    fn dispatch_data(&mut self, channel_id: u32, payload: &[u8]) -> DvcResult<Vec<SvcMessage>> {
        let name = match self.active_channels.get(&channel_id) {
            Some(n) => n.clone(),
            None => return Ok(vec![]),
        };
        let proc = match self.processors.get_mut(&name) {
            Some(p) => p,
            None => return Ok(vec![]),
        };

        let responses = proc.process(channel_id, payload)?;
        let mut messages = Vec::new();
        for msg in responses {
            messages.push(SvcMessage::new(pdu::encode_data(channel_id, &msg.data)));
        }
        Ok(messages)
    }

    /// Send data on an open DVC channel via the DRDYNVC SVC and return
    /// an `SvcMessage` ready for the `drdynvc` static channel.
    ///
    /// **Soft-Sync guard**: returns `Err` if the channel has been
    /// soft-synced to a multitransport tunnel. Sending SVC bytes for
    /// such a channel would silently bypass the routing the server
    /// agreed to in `SoftSyncResponse` and split the wire ordering
    /// across two transports. Use [`Self::route_outbound`] (which picks
    /// the correct transport automatically) for the common path.
    ///
    /// Returns `Err` if `channel_id` is not currently open or if it
    /// has an active outbound tunnel route.
    #[deprecated(
        since = "0.1.0",
        note = "use route_outbound() for routing-aware dispatch; this API \
                rejects Soft-Synced channels and will be removed once all \
                callers migrate"
    )]
    pub fn send_on_channel(&mut self, channel_id: u32, data: &[u8]) -> DvcResult<SvcMessage> {
        if !self.active_channels.contains_key(&channel_id) {
            return Err(DvcError::Protocol(String::from(
                "send_on_channel: channel not open",
            )));
        }
        if self.outbound_tunnel_for(channel_id).is_some() {
            return Err(DvcError::Protocol(alloc::format!(
                "send_on_channel: channel {channel_id} is soft-synced to a tunnel; \
                 use route_outbound() to honor the negotiated route",
            )));
        }
        Ok(SvcMessage::new(pdu::encode_data(channel_id, data)))
    }

    /// Send data on an open DVC channel, picking SVC vs multitransport
    /// tunnel based on the Soft-Sync routing table
    /// ([`Self::outbound_tunnel_for`]). Returns the encoded DVC PDU
    /// bytes wrapped in a [`DvcOutput`] tagged with the chosen route so
    /// the caller knows which transport to write to without consulting
    /// the routing table separately.
    ///
    /// Returns `Err` if `channel_id` is not currently open.
    pub fn route_outbound(&self, channel_id: u32, data: &[u8]) -> DvcResult<DvcOutput> {
        if !self.active_channels.contains_key(&channel_id) {
            return Err(DvcError::Protocol(String::from(
                "route_outbound: channel not open",
            )));
        }
        let dvc_pdu = pdu::encode_data(channel_id, data);
        Ok(match self.outbound_tunnel_for(channel_id) {
            Some(tunnel_type) => DvcOutput::Tunnel { tunnel_type, payload: dvc_pdu },
            None => DvcOutput::Svc(SvcMessage::new(dvc_pdu)),
        })
    }

    /// Inject DVC PDU bytes that arrived on a multitransport tunnel
    /// (`tunnel_type` = `TUNNELTYPE_UDPFECR` / `TUNNELTYPE_UDPFECL`).
    /// `payload` is the `HigherLayerData` field of the wrapping
    /// `RDP_TUNNEL_DATA` PDU (MS-RDPEMT §2.2.2.3); the wrapper is
    /// caller-stripped because the connector already knows which tunnel
    /// the datagram came from.
    ///
    /// Returns processor responses tagged with their outbound route —
    /// typically `Tunnel { tunnel_type, .. }` mirroring the inbound
    /// tunnel, but [`Self::outbound_tunnel_for`] may direct a response
    /// elsewhere if the routing tables disagree.
    ///
    /// Errors:
    /// - `DvcError::Protocol` if `tunnel_type` is not one the caller
    ///   has marked as ready via [`Self::notify_tunnels_ready`] —
    ///   accepting tunnel data on a transport we never advertised
    ///   would be a server-side spec violation worth surfacing.
    /// - PDU decode / processor errors propagate.
    pub fn process_tunnel_data(
        &mut self,
        tunnel_type: u32,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcOutput>> {
        if !self.available_tunnels.contains(&tunnel_type) {
            return Err(DvcError::Protocol(alloc::format!(
                "process_tunnel_data: tunnel 0x{tunnel_type:08X} not marked ready",
            )));
        }
        // MS-RDPEMT runs in DTLS message mode (one record = one
        // application message) and the existing DVC `Data` decode
        // greedily consumes the rest of the buffer, so each call must
        // carry exactly one DVC PDU (typically one `RDP_TUNNEL_DATA`'s
        // HigherLayerData).
        let mut src = ReadCursor::new(payload);
        let pdu = pdu::decode_dvc_pdu(&mut src)?;
        if src.remaining() > 0 {
            // Decoder consumed a complete PDU but bytes remain — server
            // either packed multiple PDUs (which our DTLS message-mode
            // assumption forbids) or sent a corrupt frame. Surface as an
            // error rather than silently drop.
            return Err(DvcError::Protocol(alloc::format!(
                "process_tunnel_data: {} trailing bytes after DVC PDU",
                src.remaining(),
            )));
        }
        self.process_tunnel_pdu(pdu)
    }

    /// Tunnel-side counterpart to `process_pdu`. Only data PDUs are
    /// expected here — caps / create / close / soft-sync travel on the
    /// SVC. Anything else is a protocol error.
    fn process_tunnel_pdu(&mut self, pdu: DvcPdu) -> DvcResult<Vec<DvcOutput>> {
        match pdu {
            DvcPdu::DataFirst { channel_id, total_length, data } => {
                self.handle_tunnel_fragment(channel_id, Some(total_length), &data)
            }
            DvcPdu::Data { channel_id, data } => {
                self.handle_tunnel_fragment(channel_id, None, &data)
            }
            DvcPdu::DataFirstCompressed { channel_id, total_length, data } => {
                let decompressed = self.decompress_chunk(channel_id, &data)?;
                self.handle_tunnel_fragment(channel_id, Some(total_length), &decompressed)
            }
            DvcPdu::DataCompressed { channel_id, data } => {
                let decompressed = self.decompress_chunk(channel_id, &data)?;
                self.handle_tunnel_fragment(channel_id, None, &decompressed)
            }
            other => Err(DvcError::Protocol(alloc::format!(
                "process_tunnel_data: control PDU on tunnel: {:?}",
                other,
            ))),
        }
    }

    fn handle_tunnel_fragment(
        &mut self,
        channel_id: u32,
        total_length: Option<u32>,
        data: &[u8],
    ) -> DvcResult<Vec<DvcOutput>> {
        let reassembler = match self.reassemblers.get_mut(&channel_id) {
            Some(r) => r,
            // Unknown channel — silently drop (matches SVC-side
            // behavior for unknown channels per §3.1.5.1.4).
            None => return Ok(vec![]),
        };
        let complete = match total_length {
            Some(len) => reassembler.data_first(len, data)?,
            None => reassembler.data(data)?,
        };
        if let Some(payload) = complete {
            self.dispatch_data_routed(channel_id, &payload)
        } else {
            Ok(vec![])
        }
    }

    /// Dispatch reassembled payload to the channel processor and tag
    /// each response with the outbound route picked by the routing
    /// table. Used by the tunnel ingestion path.
    fn dispatch_data_routed(
        &mut self,
        channel_id: u32,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcOutput>> {
        let name = match self.active_channels.get(&channel_id) {
            Some(n) => n.clone(),
            None => return Ok(vec![]),
        };
        let proc = match self.processors.get_mut(&name) {
            Some(p) => p,
            None => return Ok(vec![]),
        };
        let responses = proc.process(channel_id, payload)?;
        let route = self.outbound_tunnel_for(channel_id);
        let mut out = Vec::with_capacity(responses.len());
        for msg in responses {
            let dvc_pdu = pdu::encode_data(channel_id, &msg.data);
            out.push(match route {
                Some(tunnel_type) => DvcOutput::Tunnel { tunnel_type, payload: dvc_pdu },
                None => DvcOutput::Svc(SvcMessage::new(dvc_pdu)),
            });
        }
        Ok(out)
    }

    /// Look up the channel ID for a registered processor by name.
    ///
    /// Returns `None` if no channel with that name is currently open.
    pub fn channel_id_by_name(&self, name: &str) -> Option<u32> {
        self.active_channels
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .map(|(&id, _)| id)
    }
}

impl Default for DrdynvcClient {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for DrdynvcClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DrdynvcClient")
            .field("negotiated_version", &self.negotiated_version)
            .field("active_channels", &self.active_channels.len())
            .field("processors", &self.processors.len())
            .finish()
    }
}

impl AsAny for DrdynvcClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl SvcProcessor for DrdynvcClient {
    fn channel_name(&self) -> ChannelName {
        DRDYNVC
    }

    fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
        // The DRDYNVC channel waits for the server's DYNVC_CAPS.
        // No initial messages to send.
        Ok(vec![])
    }

    fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
        let mut src = ReadCursor::new(payload);
        let mut all_responses = Vec::new();

        // MS-RDPEDYC allows multiple DVC PDUs in a single SVC payload.
        while src.remaining() > 0 {
            let pdu = pdu::decode_dvc_pdu(&mut src)
                .map_err(justrdp_svc::SvcError::Decode)?;
            let responses = self.process_pdu(pdu)
                .map_err(|e| match e {
                    DvcError::Decode(d) => justrdp_svc::SvcError::Decode(d),
                    DvcError::Encode(e) => justrdp_svc::SvcError::Encode(e),
                    DvcError::Protocol(s) => justrdp_svc::SvcError::Protocol(s),
                })?;
            all_responses.extend(responses);
        }

        Ok(all_responses)
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::Never
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DvcMessage;

    /// A simple echo DVC processor for testing.
    #[derive(Debug)]
    struct EchoDvcProcessor;

    impl AsAny for EchoDvcProcessor {
        fn as_any(&self) -> &dyn core::any::Any { self }
        fn as_any_mut(&mut self) -> &mut dyn core::any::Any { self }
    }

    impl DvcProcessor for EchoDvcProcessor {
        fn channel_name(&self) -> &str { "testdvc" }

        fn start(&mut self, _channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
            Ok(vec![])
        }

        fn process(&mut self, _channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
            Ok(vec![DvcMessage::new(payload.to_vec())])
        }

        fn close(&mut self, _channel_id: u32) {}
    }

    #[test]
    fn caps_negotiation_v1() {
        let mut client = DrdynvcClient::new();
        let caps = [0x50, 0x00, 0x01, 0x00]; // CAPS_VERSION_1
        let responses = client.process(&caps).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(&responses[0].data, &[0x50, 0x00, 0x01, 0x00]); // echo v1
        assert_eq!(client.negotiated_version(), 1);
    }

    #[test]
    fn caps_negotiation_v3_clamped() {
        let mut client = DrdynvcClient::new();
        // Server sends v3 with priority charges.
        let caps: [u8; 12] = [
            0x50, 0x00, 0x03, 0x00,
            0xA8, 0x03, 0xCC, 0x0C,
            0xA2, 0x24, 0x55, 0x55,
        ];
        let responses = client.process(&caps).unwrap();
        assert_eq!(client.negotiated_version(), 3);
        // Response is 4 bytes with version=3.
        assert_eq!(&responses[0].data, &[0x50, 0x00, 0x03, 0x00]);
    }

    #[test]
    fn create_request_accepted() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));
        // Negotiate first.
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();

        // CreateRequest: channel_id=3, name="testdvc"
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        let responses = client.process(&create_req).unwrap();
        assert_eq!(responses.len(), 1);
        // CreateResponse with status=0 (OK).
        assert_eq!(&responses[0].data, &[0x10, 0x03, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn create_request_rejected_no_listener() {
        let mut client = DrdynvcClient::new();
        // No processor registered for "unknown".
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();

        let create_req = [0x10, 0x03, 0x75, 0x6E, 0x6B, 0x00]; // "unk\0"
        let responses = client.process(&create_req).unwrap();
        assert_eq!(responses.len(), 1);
        // CreationStatus should be negative (E_FAIL).
        let status_bytes = &responses[0].data[2..6];
        let status = i32::from_le_bytes(status_bytes.try_into().unwrap());
        assert!(status < 0);
    }

    #[test]
    fn data_single_echo() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        // Create channel 3.
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();

        // Send Data on channel 3: "hello"
        let data_pdu = [0x30, 0x03, b'h', b'e', b'l', b'l', b'o'];
        let responses = client.process(&data_pdu).unwrap();
        assert_eq!(responses.len(), 1);
        // Echo processor returns "hello" wrapped as Data PDU.
        let mut src = ReadCursor::new(&responses[0].data);
        let pdu = pdu::decode_dvc_pdu(&mut src).unwrap();
        match pdu {
            DvcPdu::Data { channel_id, data } => {
                assert_eq!(channel_id, 3);
                assert_eq!(data, b"hello");
            }
            _ => panic!("expected Data PDU"),
        }
    }

    #[test]
    fn data_first_reassembly() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();

        // DataFirst: channel=3, total_length=6, data="AAA"
        let data_first = pdu::encode_data_first(3, 6, b"AAA");
        let responses = client.process(&data_first).unwrap();
        assert!(responses.is_empty()); // not complete yet

        // Data: channel=3, data="BBB"
        let data = pdu::encode_data(3, b"BBB");
        let responses = client.process(&data).unwrap();
        assert_eq!(responses.len(), 1); // echo of "AAABBB"
    }

    #[test]
    fn close_echoed() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();

        // Close channel 3.
        let close = [0x40, 0x03];
        let responses = client.process(&close).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(&responses[0].data, &[0x40, 0x03]); // echo close
    }

    #[test]
    fn close_unknown_channel_no_response() {
        let mut client = DrdynvcClient::new();
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        // Close channel 99 which was never created — should be ignored.
        let close = pdu::encode_close(99);
        let responses = client.process(&close).unwrap();
        assert!(responses.is_empty());
    }

    #[test]
    fn duplicate_create_request_resets_reassembler() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();

        // First CreateRequest for channel 3.
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();

        // Start a DataFirst that won't complete.
        let data_first = pdu::encode_data_first(3, 100, b"partial");
        client.process(&data_first).unwrap();

        // Duplicate CreateRequest for channel 3 — should reset state.
        let responses = client.process(&create_req).unwrap();
        assert_eq!(responses.len(), 1); // new CreateResponse(OK)

        // New data on the channel should work independently (no leftover from prior assembly).
        let data = pdu::encode_data(3, b"fresh");
        let responses = client.process(&data).unwrap();
        assert_eq!(responses.len(), 1);
        // Echo processor echoes "fresh".
        let mut src = ReadCursor::new(&responses[0].data);
        let pdu = pdu::decode_dvc_pdu(&mut src).unwrap();
        match pdu {
            DvcPdu::Data { data, .. } => assert_eq!(data, b"fresh"),
            _ => panic!("expected Data"),
        }
    }

    #[test]
    #[allow(deprecated)] // exercising the deprecated path until callers migrate
    fn send_on_channel_open_channel() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));

        // Negotiate caps
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        // CreateRequest: channel_id=3, name="testdvc"
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();

        // Send data proactively
        let msg = client.send_on_channel(3, b"hello").unwrap();
        let mut src = ReadCursor::new(&msg.data);
        let decoded = pdu::decode_dvc_pdu(&mut src).unwrap();
        match decoded {
            DvcPdu::Data { channel_id, data } => {
                assert_eq!(channel_id, 3);
                assert_eq!(data, b"hello");
            }
            _ => panic!("expected Data"),
        }
    }

    #[test]
    #[allow(deprecated)]
    fn send_on_channel_closed_channel_returns_error() {
        let mut client = DrdynvcClient::new();
        assert!(client.send_on_channel(99, b"data").is_err());
    }

    #[test]
    fn channel_id_by_name_lookup() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));

        // Not open yet
        assert_eq!(client.channel_id_by_name("testdvc"), None);

        // Negotiate + open channel
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();

        assert_eq!(client.channel_id_by_name("testdvc"), Some(3));
        assert_eq!(client.channel_id_by_name("nonexistent"), None);
    }

    #[test]
    fn soft_sync_request_no_op_when_no_tunnels_ready() {
        // No tunnel marked ready → declining the Soft-Sync is the
        // spec-permitted default (MS-RDPEDYC §3.2.5.3.1: absence of
        // Response keeps DVC traffic on the SVC).
        let mut client = DrdynvcClient::new();
        let req = pdu::encode_soft_sync_request(
            pdu::SOFT_SYNC_TCP_FLUSHED | pdu::SOFT_SYNC_CHANNEL_LIST_PRESENT,
            &[pdu::SoftSyncChannelList {
                tunnel_type: pdu::TUNNELTYPE_UDPFECR,
                dvc_ids: vec![3],
            }],
        )
        .unwrap();
        let responses = client.process(&req).expect("Soft-Sync Request must decode");
        assert!(responses.is_empty(), "no tunnels ready → no Response");
        // Routing tables remain empty.
        assert!(client.inbound_tunnel_for(3).is_none());
        assert!(client.outbound_tunnel_for(3).is_none());
    }

    #[test]
    fn soft_sync_request_with_ready_tunnel_emits_response() {
        let mut client = DrdynvcClient::new();
        client.notify_tunnels_ready(&[pdu::TUNNELTYPE_UDPFECR]);
        let req = pdu::encode_soft_sync_request(
            pdu::SOFT_SYNC_TCP_FLUSHED | pdu::SOFT_SYNC_CHANNEL_LIST_PRESENT,
            &[pdu::SoftSyncChannelList {
                tunnel_type: pdu::TUNNELTYPE_UDPFECR,
                dvc_ids: vec![3, 7],
            }],
        )
        .unwrap();
        let responses = client.process(&req).expect("Soft-Sync Request must decode");
        assert_eq!(responses.len(), 1, "exactly one Response emitted");

        // Decode the Response to verify TunnelsToSwitch.
        let mut src = ReadCursor::new(&responses[0].data);
        let pdu = pdu::decode_dvc_pdu(&mut src).expect("Response decodes");
        match pdu {
            DvcPdu::SoftSyncResponse { tunnels_to_switch } => {
                assert_eq!(tunnels_to_switch, vec![pdu::TUNNELTYPE_UDPFECR]);
            }
            other => panic!("expected SoftSyncResponse, got {other:?}"),
        }

        // Routing tables populated: both inbound (server → client) and
        // outbound (client → server) for the listed channels.
        assert_eq!(client.inbound_tunnel_for(3), Some(pdu::TUNNELTYPE_UDPFECR));
        assert_eq!(client.inbound_tunnel_for(7), Some(pdu::TUNNELTYPE_UDPFECR));
        assert_eq!(client.outbound_tunnel_for(3), Some(pdu::TUNNELTYPE_UDPFECR));
        assert_eq!(client.outbound_tunnel_for(7), Some(pdu::TUNNELTYPE_UDPFECR));
        // Unrelated channel stays on the SVC.
        assert!(client.inbound_tunnel_for(99).is_none());
        assert!(client.outbound_tunnel_for(99).is_none());
    }

    #[test]
    fn soft_sync_request_partial_tunnel_availability() {
        // Server requests both UDPFECR and UDPFECL, but only UDPFECR
        // is ready. UDPFECL channels stay on the SVC; UDPFECR channels
        // get routed; Response advertises only UDPFECR.
        let mut client = DrdynvcClient::new();
        client.notify_tunnels_ready(&[pdu::TUNNELTYPE_UDPFECR]);
        let req = pdu::encode_soft_sync_request(
            pdu::SOFT_SYNC_TCP_FLUSHED | pdu::SOFT_SYNC_CHANNEL_LIST_PRESENT,
            &[
                pdu::SoftSyncChannelList {
                    tunnel_type: pdu::TUNNELTYPE_UDPFECR,
                    dvc_ids: vec![3],
                },
                pdu::SoftSyncChannelList {
                    tunnel_type: pdu::TUNNELTYPE_UDPFECL,
                    dvc_ids: vec![7],
                },
            ],
        )
        .unwrap();
        let responses = client.process(&req).expect("Soft-Sync Request must decode");
        assert_eq!(responses.len(), 1);

        let mut src = ReadCursor::new(&responses[0].data);
        match pdu::decode_dvc_pdu(&mut src).unwrap() {
            DvcPdu::SoftSyncResponse { tunnels_to_switch } => {
                assert_eq!(tunnels_to_switch, vec![pdu::TUNNELTYPE_UDPFECR]);
            }
            other => panic!("expected SoftSyncResponse, got {other:?}"),
        }

        assert_eq!(client.inbound_tunnel_for(3), Some(pdu::TUNNELTYPE_UDPFECR));
        // Channel 7 was assigned to UDPFECL (not ready) → unrouted.
        assert!(client.inbound_tunnel_for(7).is_none());
    }

    #[test]
    fn soft_sync_request_duplicate_channel_id_rejected() {
        // Same channel_id appears under two different tunnel types —
        // MS-RDPEDYC §2.2.5.1.1 MUST NOT.
        let mut client = DrdynvcClient::new();
        client.notify_tunnels_ready(&[pdu::TUNNELTYPE_UDPFECR, pdu::TUNNELTYPE_UDPFECL]);
        let req = pdu::encode_soft_sync_request(
            pdu::SOFT_SYNC_TCP_FLUSHED | pdu::SOFT_SYNC_CHANNEL_LIST_PRESENT,
            &[
                pdu::SoftSyncChannelList {
                    tunnel_type: pdu::TUNNELTYPE_UDPFECR,
                    dvc_ids: vec![3],
                },
                pdu::SoftSyncChannelList {
                    tunnel_type: pdu::TUNNELTYPE_UDPFECL,
                    dvc_ids: vec![3],
                },
            ],
        )
        .unwrap();
        let err = client.process(&req).expect_err("must reject duplicate channel");
        match err {
            justrdp_svc::SvcError::Protocol(_) => {}
            other => panic!("expected SvcError::Protocol, got {other:?}"),
        }
        // No partial state left behind.
        assert!(client.inbound_tunnel_for(3).is_none());
    }

    #[test]
    fn outbound_tunnel_for_returns_none_when_tunnel_not_in_response() {
        // Edge: channel was inbound-routed via SoftSyncRequest, but the
        // Response excluded its tunnel (e.g. tunnel disappeared). Future
        // re-routing isn't covered, but `outbound_tunnel_for` must respect
        // `outbound_tunnels` and not blindly mirror `channel_to_tunnel`.
        let mut client = DrdynvcClient::new();
        client.notify_tunnels_ready(&[pdu::TUNNELTYPE_UDPFECR]);
        let req = pdu::encode_soft_sync_request(
            pdu::SOFT_SYNC_TCP_FLUSHED | pdu::SOFT_SYNC_CHANNEL_LIST_PRESENT,
            &[pdu::SoftSyncChannelList {
                tunnel_type: pdu::TUNNELTYPE_UDPFECR,
                dvc_ids: vec![3],
            }],
        )
        .unwrap();
        client.process(&req).unwrap();
        // Sanity: outbound currently allowed.
        assert_eq!(client.outbound_tunnel_for(3), Some(pdu::TUNNELTYPE_UDPFECR));
        // Simulate "client decided to stop writing on UDPFECR" by clearing
        // the outbound set directly. (No public API to mutate this — it
        // only changes when a new SoftSyncResponse is constructed. Use
        // an internal mutation here to stress the lookup logic.)
        client.outbound_tunnels.clear();
        assert!(client.outbound_tunnel_for(3).is_none());
        // Inbound stays — server still uses the tunnel for that channel.
        assert_eq!(client.inbound_tunnel_for(3), Some(pdu::TUNNELTYPE_UDPFECR));
    }

    #[test]
    fn soft_sync_response_from_server_rejected() {
        // Server-bound PDU received by the client → protocol error.
        let mut client = DrdynvcClient::new();
        let resp = pdu::encode_soft_sync_response(&[pdu::TUNNELTYPE_UDPFECR]).unwrap();
        let err = client.process(&resp).expect_err("must reject client-only PDU");
        match err {
            justrdp_svc::SvcError::Protocol(_) => {}
            other => panic!("expected SvcError::Protocol, got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Soft-Sync routing — outbound + inbound tunnel APIs (Commit E.2)
    // ──────────────────────────────────────────────────────────────────

    /// Drive a client through Caps + Create + SoftSyncRequest so that
    /// channel 3 ("testdvc") is open and routed via UDPFECR. Returns
    /// the configured client.
    fn client_with_soft_synced_channel() -> DrdynvcClient {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));
        client.notify_tunnels_ready(&[pdu::TUNNELTYPE_UDPFECR]);
        // Caps v1 → CreateRequest channel_id=3 → SoftSync over UDPFECR.
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();
        let soft_sync_req = pdu::encode_soft_sync_request(
            pdu::SOFT_SYNC_TCP_FLUSHED | pdu::SOFT_SYNC_CHANNEL_LIST_PRESENT,
            &[pdu::SoftSyncChannelList {
                tunnel_type: pdu::TUNNELTYPE_UDPFECR,
                dvc_ids: vec![3],
            }],
        )
        .unwrap();
        let resp = client.process(&soft_sync_req).unwrap();
        assert_eq!(resp.len(), 1, "SoftSyncResponse must be emitted");
        client
    }

    #[test]
    fn route_outbound_tunnel_for_soft_synced_channel() {
        let client = client_with_soft_synced_channel();
        let out = client.route_outbound(3, b"hello").unwrap();
        match out {
            DvcOutput::Tunnel { tunnel_type, payload } => {
                assert_eq!(tunnel_type, pdu::TUNNELTYPE_UDPFECR);
                // The payload is a DYNVC_DATA frame for channel 3 carrying "hello".
                let mut src = ReadCursor::new(&payload);
                match pdu::decode_dvc_pdu(&mut src).unwrap() {
                    DvcPdu::Data { channel_id, data } => {
                        assert_eq!(channel_id, 3);
                        assert_eq!(data, b"hello");
                    }
                    other => panic!("expected DYNVC_DATA, got {other:?}"),
                }
            }
            DvcOutput::Svc(_) => panic!("channel 3 must route via UDPFECR"),
        }
    }

    #[test]
    fn route_outbound_svc_for_unrouted_channel() {
        // No Soft-Sync, just a regular open channel.
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();
        let out = client.route_outbound(3, b"hello").unwrap();
        match out {
            DvcOutput::Svc(msg) => {
                let mut src = ReadCursor::new(&msg.data);
                match pdu::decode_dvc_pdu(&mut src).unwrap() {
                    DvcPdu::Data { channel_id, data } => {
                        assert_eq!(channel_id, 3);
                        assert_eq!(data, b"hello");
                    }
                    other => panic!("expected DYNVC_DATA, got {other:?}"),
                }
            }
            DvcOutput::Tunnel { .. } => panic!("non-soft-synced channel must use SVC"),
        }
    }

    #[test]
    fn route_outbound_unknown_channel_errors() {
        let client = DrdynvcClient::new();
        assert!(client.route_outbound(99, b"x").is_err());
    }

    #[test]
    fn process_tunnel_data_dispatches_and_routes_response() {
        // End-to-end: server sends DYNVC_DATA over the UDPFECR tunnel
        // to soft-synced channel 3. Echo processor responds; response
        // must be tagged for the same tunnel.
        let mut client = client_with_soft_synced_channel();
        let server_frame = pdu::encode_data(3, b"hello");
        let outputs = client
            .process_tunnel_data(pdu::TUNNELTYPE_UDPFECR, &server_frame)
            .unwrap();
        assert_eq!(outputs.len(), 1, "echo emits exactly one response");
        match &outputs[0] {
            DvcOutput::Tunnel { tunnel_type, payload } => {
                assert_eq!(*tunnel_type, pdu::TUNNELTYPE_UDPFECR);
                let mut src = ReadCursor::new(payload);
                match pdu::decode_dvc_pdu(&mut src).unwrap() {
                    DvcPdu::Data { channel_id, data } => {
                        assert_eq!(channel_id, 3);
                        assert_eq!(data, b"hello");
                    }
                    other => panic!("expected DYNVC_DATA, got {other:?}"),
                }
            }
            DvcOutput::Svc(_) => panic!("response must follow inbound tunnel"),
        }
    }

    #[test]
    fn process_tunnel_data_rejects_unmarked_tunnel() {
        // UDPFECR is the only one ready; UDPFECL data must error.
        let mut client = client_with_soft_synced_channel();
        let server_frame = pdu::encode_data(3, b"hi");
        let err = client
            .process_tunnel_data(pdu::TUNNELTYPE_UDPFECL, &server_frame)
            .unwrap_err();
        match err {
            DvcError::Protocol(msg) => assert!(msg.contains("not marked ready")),
            other => panic!("expected DvcError::Protocol, got {other:?}"),
        }
    }

    #[test]
    fn process_tunnel_data_rejects_control_pdu() {
        // CreateRequest, Caps, Close etc. MUST come over the SVC,
        // never the tunnel. A server bug sending one over UDP should
        // surface as a protocol error.
        let mut client = client_with_soft_synced_channel();
        // Build a DYNVC_CLOSE for channel 3.
        let close_frame = pdu::encode_close(3);
        let err = client
            .process_tunnel_data(pdu::TUNNELTYPE_UDPFECR, &close_frame)
            .unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn process_tunnel_data_unknown_channel_silently_dropped() {
        // Inbound tunnel data for a channel we don't have open should
        // be dropped without error (defensive — server timing race).
        let mut client = client_with_soft_synced_channel();
        let server_frame = pdu::encode_data(99, b"orphan");
        let outputs = client
            .process_tunnel_data(pdu::TUNNELTYPE_UDPFECR, &server_frame)
            .unwrap();
        assert!(outputs.is_empty());
    }

    #[test]
    fn second_soft_sync_request_accumulates_outbound_tunnels() {
        // After a first SoftSyncRequest assigns channel 3 to UDPFECR,
        // a second request adding channel 5 on UDPFECL must not erase
        // channel 3's outbound route.
        let mut client = DrdynvcClient::new();
        client.notify_tunnels_ready(&[pdu::TUNNELTYPE_UDPFECR, pdu::TUNNELTYPE_UDPFECL]);

        let req1 = pdu::encode_soft_sync_request(
            pdu::SOFT_SYNC_TCP_FLUSHED | pdu::SOFT_SYNC_CHANNEL_LIST_PRESENT,
            &[pdu::SoftSyncChannelList {
                tunnel_type: pdu::TUNNELTYPE_UDPFECR,
                dvc_ids: vec![3],
            }],
        )
        .unwrap();
        client.process(&req1).unwrap();
        assert_eq!(client.outbound_tunnel_for(3), Some(pdu::TUNNELTYPE_UDPFECR));

        let req2 = pdu::encode_soft_sync_request(
            pdu::SOFT_SYNC_TCP_FLUSHED | pdu::SOFT_SYNC_CHANNEL_LIST_PRESENT,
            &[pdu::SoftSyncChannelList {
                tunnel_type: pdu::TUNNELTYPE_UDPFECL,
                dvc_ids: vec![5],
            }],
        )
        .unwrap();
        client.process(&req2).unwrap();
        // Both channels keep their tunnel routes.
        assert_eq!(client.outbound_tunnel_for(3), Some(pdu::TUNNELTYPE_UDPFECR));
        assert_eq!(client.outbound_tunnel_for(5), Some(pdu::TUNNELTYPE_UDPFECL));
    }

    #[test]
    #[allow(deprecated)]
    fn send_on_channel_rejects_soft_synced_channel() {
        // Soft-Sync makes channel 3 tunnel-routed; the legacy SVC-only
        // send_on_channel must refuse rather than silently mis-route.
        let mut client = client_with_soft_synced_channel();
        let err = client.send_on_channel(3, b"oops").unwrap_err();
        match err {
            DvcError::Protocol(msg) => assert!(msg.contains("soft-synced")),
            other => panic!("expected DvcError::Protocol, got {other:?}"),
        }
        // route_outbound on the same channel still works.
        assert!(matches!(
            client.route_outbound(3, b"ok"),
            Ok(DvcOutput::Tunnel { .. }),
        ));
    }

    #[test]
    fn process_tunnel_data_handles_fragmented_payload() {
        // Server splits "hello world" across two RDP_TUNNEL_DATA PDUs
        // on UDPFECR (DataFirst then Data continuation). Each arrives
        // in its own `process_tunnel_data` call (DTLS message mode).
        // The first yields no output (incomplete); the second carries
        // the reassembled message and the echo response.
        let mut client = client_with_soft_synced_channel();
        let part1 = pdu::encode_data_first(3, b"hello world".len() as u32, b"hello ");
        let part2 = pdu::encode_data(3, b"world");

        let out1 = client
            .process_tunnel_data(pdu::TUNNELTYPE_UDPFECR, &part1)
            .unwrap();
        assert!(out1.is_empty(), "first fragment: still incomplete");

        let out2 = client
            .process_tunnel_data(pdu::TUNNELTYPE_UDPFECR, &part2)
            .unwrap();
        assert_eq!(out2.len(), 1, "second fragment completes the message");
        match &out2[0] {
            DvcOutput::Tunnel { tunnel_type: _, payload } => {
                let mut src = ReadCursor::new(payload);
                match pdu::decode_dvc_pdu(&mut src).unwrap() {
                    DvcPdu::Data { channel_id, data } => {
                        assert_eq!(channel_id, 3);
                        assert_eq!(data, b"hello world");
                    }
                    other => panic!("expected DYNVC_DATA, got {other:?}"),
                }
            }
            other => panic!("expected Tunnel, got {other:?}"),
        }
    }
}
