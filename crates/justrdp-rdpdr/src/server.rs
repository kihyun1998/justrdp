#![forbid(unsafe_code)]

//! Server-side device redirection channel processor -- MS-RDPEFS server role.
//!
//! Mirror of [`crate::RdpdrClient`] for the server direction. Drives the
//! MS-RDPEFS 1.3.1 initialization sequence:
//!
//! ```text
//! Server Announce (2.2.2.2)         ── start()
//!     ── client ──▶ Client Announce Reply (2.2.2.3)
//!     ── client ──▶ Client Name (2.2.2.4)
//! Server Core Capability Request (2.2.2.7)   [S2]
//!     ── client ──▶ Client Core Capability Response (2.2.2.8)
//! Server Client ID Confirm (2.2.2.6)         [S2]
//!     ── client ──▶ Device List Announce (2.2.3.1)   [S3]
//! Server Device Announce Response (2.2.2.1)  [S3]
//! ```
//!
//! S1 (this commit) covers the announce/name half of the exchange:
//! [`FilesystemServer::start`] emits the Server Announce PDU, and
//! `process()` decodes Client Announce Reply + Client Name. Capability
//! negotiation, device list, and IRP emit/completion arrive in S2/S3.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_svc::{
    ChannelName, CompressionCondition, SvcError, SvcMessage, SvcProcessor, SvcResult,
    SvcServerProcessor, RDPDR,
};

use crate::pdu::capability::{
    CapabilityRequestPdu, CapabilitySet, ExtendedPdu, ExtraFlags1,
    GENERAL_CAPABILITY_VERSION_02, GeneralCapabilitySet, IoCode1, RDPDR_MAJOR_RDP_VERSION,
};
use crate::pdu::device::{DeviceAnnounceResponsePdu, DeviceListAnnouncePdu};
use crate::pdu::header::{Component, PacketId, SharedHeader};
use crate::pdu::init::{
    ClientAnnounceReply, ClientNameRequest, ServerAnnounceRequest, ServerClientIdConfirm,
};
use crate::pdu::irp::{
    DeviceIoRequest, DeviceIoResponse, MajorFunction, MinorFunction, STATUS_SUCCESS,
};

/// Highest minor version this server speaks. The negotiated minor version
/// is `min(server_announce.version_minor, client_announce_reply.version_minor)`
/// per MS-RDPEFS 2.2.2.3 -- captured in [`FilesystemServer::version_minor`]
/// once the client reply lands.
const VERSION_MINOR_DEFAULT: u16 = 0x000C;

/// Server-side RDPDR channel state -- MS-RDPEFS 1.3.1 abstract data model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilesystemServerState {
    /// `start()` has not been called yet.
    NotStarted,
    /// Server emitted Server Announce; awaiting Client Announce Reply.
    WaitingForClientAnnounce,
    /// Reply received; awaiting the Client Name PDU before moving on
    /// to capability negotiation. The two PDUs always arrive in this
    /// order per §1.3.1, but a misbehaving client could swap them --
    /// the state machine ignores out-of-order PDUs rather than
    /// erroring (matching the cliprdr/rdpsnd server convention).
    WaitingForClientName,
    /// Capability negotiation phase. The server has emitted Server
    /// Core Capability Request + Server Client ID Confirm and is
    /// awaiting the client's Client Core Capability Response.
    WaitingForClientCapability,
    /// Capability response received; the server has finalized its
    /// negotiated I/O code set and is awaiting the Device List Announce
    /// PDU. S3 will move on from here.
    WaitingForDeviceList,
    /// Device list received and acknowledged. The server may now emit
    /// IRPs (Create / Close / Read / Write) and dispatches incoming
    /// `DeviceIoCompletion` PDUs to the application handler.
    Active,
}

/// Soft cap on how many IRPs may be in flight at once. With the RDPDR
/// completion correlation done by `completion_id` (u32), this limit
/// only protects against a buggy caller emitting an unbounded number
/// of requests without ever consuming the responses; the spec itself
/// does not mandate a ceiling.
const MAX_INFLIGHT: usize = 4096;

/// A device the server intends to drive on behalf of the client side.
///
/// Server-side IRPs (CREATE/READ/WRITE/...) are addressed by `device_id`.
/// The server learns about devices through the Client Device List
/// Announce PDU and tracks them here so application code can fan out
/// I/O to specific device IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncedDevice {
    /// Client-assigned unique device identifier.
    pub device_id: u32,
    /// Device class -- raw u32 from MS-RDPEFS 2.2.1.3 DeviceType.
    pub device_type: u32,
    /// PreferredDosName (e.g. "C:", "PRN1", "SCARD").
    pub preferred_dos_name: String,
    /// Per-device-type extra payload (e.g. UTF-16LE display name for
    /// drives, printer-specific data for printers). Empty for devices
    /// with no extra metadata.
    pub device_data: Vec<u8>,
}

/// Decoded `DR_DEVICE_IOCOMPLETION` payload, dispatched to the
/// application handler with the original `MajorFunction` already
/// resolved. The `io_status` (NTSTATUS) and other completion-header
/// fields are passed alongside.
///
/// MS-RDPEFS 2.2.1.5 + per-major variants in §2.2.1.5.x.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoCompletion {
    /// `DR_CREATE_RSP` (2.2.1.5.1): FileId(u32) + Information(u8). The
    /// `Information` field encodes the action taken (FILE_OPENED /
    /// FILE_OVERWRITTEN / FILE_SUPERSEDED).
    Create {
        /// Server-assigned file handle to use in subsequent IRPs.
        file_id: u32,
        /// MS-SMB2 2.2.14 Information value.
        information: u8,
    },
    /// `DR_CLOSE_RSP` (2.2.1.5.2): 4 bytes padding -- we discard it.
    Close,
    /// `DR_READ_RSP` (2.2.1.5.3): Length(u32) + ReadData[]. We surface
    /// `ReadData` as `Vec<u8>` (length-prefix already consumed).
    Read {
        /// Bytes the client returned. Empty on error.
        data: Vec<u8>,
    },
    /// `DR_WRITE_RSP` (2.2.1.5.4): Length(u32) + Padding(u8) -- the
    /// number of bytes the client successfully wrote.
    Write {
        /// Bytes the client successfully wrote (may be < requested).
        bytes_written: u32,
    },
}

/// Tunables for the server-side RDPDR channel processor.
#[derive(Debug, Clone)]
pub struct FilesystemServerConfig {
    /// Initial value for the `clientId` field of the Server Announce PDU.
    /// MS-RDPEFS 2.2.2.2: this id is reused (or replaced by the server)
    /// in the subsequent Server Client ID Confirm; the spec allows any
    /// 32-bit value the server picks.
    pub initial_client_id: u32,
    /// Highest minor version this server is willing to speak.
    pub max_version_minor: u16,
    /// Major IRPs the server intends to drive. Advertised in the Server
    /// Core Capability Request `ioCode1` field (MS-RDPEFS 2.2.2.7.1).
    /// Defaults to CREATE/CLOSE/READ/WRITE -- the §11.2c-3 first-cut
    /// scope -- callers can widen it for QUERY_INFO / DIRECTORY_CONTROL
    /// once the IRP encoders ship in S3+.
    pub server_io_code1: IoCode1,
}

impl FilesystemServerConfig {
    /// Default config: clientId=1, max minor version=0x000C
    /// (Windows Server 2012 / latest published spec level), IRP set
    /// CREATE / CLOSE / READ / WRITE.
    pub fn new() -> Self {
        Self {
            initial_client_id: 1,
            max_version_minor: VERSION_MINOR_DEFAULT,
            server_io_code1: IoCode1::RDPDR_IRP_MJ_CREATE
                .union(IoCode1::RDPDR_IRP_MJ_CLOSE)
                .union(IoCode1::RDPDR_IRP_MJ_READ)
                .union(IoCode1::RDPDR_IRP_MJ_WRITE),
        }
    }
}

impl Default for FilesystemServerConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Application-side filesystem handler invoked by [`FilesystemServer`].
///
/// S1/S2 expose name + capability notifications; device-announce and
/// IO-completion callbacks land in S3. The trait is `Send` so it can
/// live across async boundaries.
pub trait RdpServerFilesystemHandler: Send {
    /// Client identified itself with a Client Name Request PDU
    /// (MS-RDPEFS 2.2.2.4). `computer_name` is the decoded ASCII or
    /// UTF-16LE name; `unicode` mirrors the wire UnicodeFlag for
    /// callers that need to know which form was used.
    fn on_client_name(&mut self, _computer_name: &str, _unicode: bool) {}

    /// Client Core Capability Response (MS-RDPEFS 2.2.2.8) arrived.
    /// `negotiated_io_code1` is the bitwise AND of the server's
    /// advertised set and the client's reported support -- only IRPs
    /// in this intersection are guaranteed to round-trip.
    /// `client_capability_sets` is the raw decoded list (General /
    /// Printer / Drive / SmartCard / Port) so callers can inspect the
    /// negotiated General version (V1 vs V2) and any present
    /// special-type counts.
    fn on_client_capabilities(
        &mut self,
        _negotiated_io_code1: IoCode1,
        _client_capability_sets: &[CapabilitySet],
    ) {
    }

    /// Client announced a device via Device List Announce
    /// (MS-RDPEFS 2.2.3.1). The implementation returns the NTSTATUS
    /// to put on the wire in the matching Server Device Announce
    /// Response (2.2.2.1). Default: `STATUS_SUCCESS` (accept).
    ///
    /// Returning a non-zero NTSTATUS rejects the device; the server
    /// continues to track it locally so subsequent
    /// [`FilesystemServer::announced_devices`] queries reflect the
    /// full announce, but issuing IRPs to a rejected device will
    /// produce client-side errors.
    fn on_device_announce(&mut self, _device: &AnnouncedDevice) -> u32 {
        STATUS_SUCCESS
    }

    /// Client responded to a server-emitted IRP with
    /// `DR_DEVICE_IOCOMPLETION` (MS-RDPEFS 2.2.1.5). Arguments echo
    /// the completion header plus the typed per-major payload
    /// resolved against the in-flight queue.
    fn on_io_completion(
        &mut self,
        _device_id: u32,
        _completion_id: u32,
        _io_status: u32,
        _completion: IoCompletion,
    ) {
    }
}

/// Server-side RDPDR SVC channel processor.
///
/// `start()` emits the Server Announce PDU (MS-RDPEFS 2.2.2.2);
/// subsequent `process()` calls drive the §1.3.1 handshake and -- once
/// extended in S2/S3 -- relay device-announce and IRP traffic to the
/// application's [`RdpServerFilesystemHandler`].
pub struct FilesystemServer {
    state: FilesystemServerState,
    handler: Box<dyn RdpServerFilesystemHandler>,
    config: FilesystemServerConfig,
    /// Client identifier to put on the wire. Initialised from
    /// `config.initial_client_id`; may be rewritten in S2 when the
    /// Client Announce Reply lands (the spec allows the client to
    /// echo or replace the server's id).
    client_id: u32,
    /// Negotiated protocol minor version. Initialised from
    /// `config.max_version_minor`; lowered to `min(server, client)` once
    /// the Client Announce Reply arrives.
    version_minor: u16,
    /// Most recent Client Name received from the client, retained for
    /// inspection / logging by application code.
    client_computer_name: Option<String>,
    /// Intersection of the server-advertised IRP set and the client's
    /// reported support, populated when the Client Core Capability
    /// Response arrives. Defaults to `IoCode1::from_bits(0)` (no IRP
    /// guaranteed) before the response lands.
    negotiated_io_code1: IoCode1,
    /// Devices announced by the client via Device List Announce, in
    /// order. Populated on `WaitingForDeviceList -> Active` transition
    /// and grown by subsequent announces.
    announced_devices: Vec<AnnouncedDevice>,
    /// Counter for the next outgoing IRP `completion_id`. Starts at 0
    /// and rolls over freely (the spec uses u32 with no explicit
    /// wrap-around handling; collision is statistically vanishing).
    next_completion_id: u32,
    /// Tracks which `MajorFunction` was associated with each emitted
    /// `completion_id` so the IO completion decoder can reach the
    /// correct per-major payload parser. Bounded at `MAX_INFLIGHT`.
    inflight: BTreeMap<u32, MajorFunction>,
}

impl AsAny for FilesystemServer {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl core::fmt::Debug for FilesystemServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FilesystemServer")
            .field("state", &self.state)
            .field("client_id", &self.client_id)
            .field("version_minor", &self.version_minor)
            .field("client_computer_name", &self.client_computer_name)
            .finish()
    }
}

impl FilesystemServer {
    /// Construct a server processor backed by `handler`.
    pub fn new(handler: Box<dyn RdpServerFilesystemHandler>) -> Self {
        Self::with_config(handler, FilesystemServerConfig::new())
    }

    /// Construct a server processor with explicit configuration.
    pub fn with_config(
        handler: Box<dyn RdpServerFilesystemHandler>,
        config: FilesystemServerConfig,
    ) -> Self {
        let client_id = config.initial_client_id;
        let version_minor = config.max_version_minor;
        Self {
            state: FilesystemServerState::NotStarted,
            handler,
            config,
            client_id,
            version_minor,
            client_computer_name: None,
            negotiated_io_code1: IoCode1::from_bits(0),
            announced_devices: Vec::new(),
            next_completion_id: 0,
            inflight: BTreeMap::new(),
        }
    }

    /// Currently negotiated protocol minor version. Equal to
    /// `config.max_version_minor` until the Client Announce Reply lands;
    /// thereafter `min(server, client)` per MS-RDPEFS 2.2.2.3.
    pub fn version_minor(&self) -> u16 {
        self.version_minor
    }

    /// Client identifier currently in flight. Tracks the last value the
    /// server has either advertised (Server Announce) or learnt from the
    /// client (Client Announce Reply). Useful for logging / diagnostics.
    pub fn client_id(&self) -> u32 {
        self.client_id
    }

    /// Most recent Client Name received, or `None` if the client has
    /// not sent one yet. Mirrors the value passed to
    /// [`RdpServerFilesystemHandler::on_client_name`].
    pub fn client_computer_name(&self) -> Option<&str> {
        self.client_computer_name.as_deref()
    }

    /// Bitwise intersection of `config.server_io_code1` and the client's
    /// reported `ioCode1`. Equals `IoCode1::from_bits(0)` until the
    /// Client Core Capability Response arrives.
    pub fn negotiated_io_code1(&self) -> IoCode1 {
        self.negotiated_io_code1
    }

    /// Devices the client has announced over the lifetime of this
    /// processor. Order is announce order; the list does not collapse
    /// duplicate `device_id`s if the client re-announces.
    pub fn announced_devices(&self) -> &[AnnouncedDevice] {
        &self.announced_devices
    }

    /// Whether the processor has reached the `Active` state -- IRP
    /// emit is only valid after this becomes true.
    pub fn is_active(&self) -> bool {
        self.state == FilesystemServerState::Active
    }

    /// Number of IRPs the server has emitted but not yet seen the
    /// completion for. Useful for back-pressure logic in callers.
    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    /// Encode `body` framed by the RDPDR shared header.
    fn encode_message<T: Encode>(
        component: Component,
        packet_id: PacketId,
        body: &T,
    ) -> SvcResult<SvcMessage> {
        let header = SharedHeader::new(component, packet_id);
        let total = header.size() + body.size();
        let mut buf = alloc::vec![0u8; total];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor)?;
        body.encode(&mut cursor)?;
        Ok(SvcMessage::new(buf))
    }

    /// Build the Server Announce Request -- MS-RDPEFS 2.2.2.2.
    fn build_server_announce(&self) -> SvcResult<SvcMessage> {
        let body = ServerAnnounceRequest {
            version_major: 0x0001,
            version_minor: self.config.max_version_minor,
            client_id: self.config.initial_client_id,
        };
        Self::encode_message(Component::Core, PacketId::ServerAnnounce, &body)
    }

    /// Build the Server Core Capability Request -- MS-RDPEFS 2.2.2.7.
    /// Advertises `config.server_io_code1` and the standard extended-PDU
    /// flags for device removal / display name / user-logged-on
    /// notifications. Drive cap uses V2 so the client knows the server
    /// understands the V2 wire form (the PDU only encodes the cap
    /// header so this is informational).
    fn build_capability_request(&self) -> SvcResult<SvcMessage> {
        let general = GeneralCapabilitySet {
            os_type: 0,
            os_version: 0,
            protocol_major_version: RDPDR_MAJOR_RDP_VERSION,
            protocol_minor_version: self.version_minor,
            io_code1: self.config.server_io_code1,
            extended_pdu: ExtendedPdu::RDPDR_DEVICE_REMOVE_PDUS
                .union(ExtendedPdu::RDPDR_CLIENT_DISPLAY_NAME_PDU)
                .union(ExtendedPdu::RDPDR_USER_LOGGEDON_PDU),
            extra_flags1: ExtraFlags1::NONE,
            // V2 -- carries specialTypeDeviceCap (0 here; the server
            // doesn't run a smartcard backend in this scope).
            special_type_device_cap: Some(0),
        };
        let caps = CapabilityRequestPdu::new(alloc::vec![
            CapabilitySet::General(general),
            CapabilitySet::Drive {
                version: GENERAL_CAPABILITY_VERSION_02,
            },
        ]);
        Self::encode_message(Component::Core, PacketId::ServerCapability, &caps)
    }

    /// Build the Server Client ID Confirm -- MS-RDPEFS 2.2.2.6.
    /// Emitted in the same burst as the Server Capability Request.
    fn build_client_id_confirm(&self) -> SvcResult<SvcMessage> {
        let body = ServerClientIdConfirm {
            version_major: 0x0001,
            version_minor: self.version_minor,
            client_id: self.client_id,
        };
        Self::encode_message(Component::Core, PacketId::ClientIdConfirm, &body)
    }

    /// Dispatch a decoded RDPDR PDU. Out-of-state and unknown PDUs are
    /// silently dropped (matching `RdpdrClient::handle_pdu`).
    fn handle_pdu(
        &mut self,
        header: &SharedHeader,
        body: &mut ReadCursor<'_>,
    ) -> SvcResult<Vec<SvcMessage>> {
        match (header.component, header.packet_id) {
            // Client Announce Reply -- MS-RDPEFS 2.2.2.3 (PacketId::ClientIdConfirm,
            // shared with Server Client ID Confirm; direction is implied by
            // the channel side).
            (Component::Core, PacketId::ClientIdConfirm) => {
                if self.state != FilesystemServerState::WaitingForClientAnnounce {
                    return Ok(Vec::new());
                }
                let reply = ClientAnnounceReply::decode(body)?;
                // Negotiate min(server, client) per §2.2.2.3.
                self.version_minor =
                    self.config.max_version_minor.min(reply.version_minor);
                // The spec says the client MAY replace the server's id;
                // honour whatever it sent so subsequent emits stay in sync.
                self.client_id = reply.client_id;
                self.state = FilesystemServerState::WaitingForClientName;
                Ok(Vec::new())
            }

            // Client Name Request -- MS-RDPEFS 2.2.2.4
            (Component::Core, PacketId::ClientName) => {
                if self.state != FilesystemServerState::WaitingForClientName {
                    return Ok(Vec::new());
                }
                let name = ClientNameRequest::decode(body)?;
                self.handler.on_client_name(&name.computer_name, name.unicode);
                self.client_computer_name = Some(name.computer_name);
                self.state = FilesystemServerState::WaitingForClientCapability;
                // MS-RDPEFS 1.3.1: server replies to Client Name with its
                // Capability Request followed by Client ID Confirm. The
                // two PDUs are emitted as a burst so the client can pair
                // them up (RdpdrClient drives both transitions on this
                // pair).
                Ok(alloc::vec![
                    self.build_capability_request()?,
                    self.build_client_id_confirm()?,
                ])
            }

            // Client Core Capability Response -- MS-RDPEFS 2.2.2.8 (same
            // wire shape as the request: numCaps + cap-set list).
            (Component::Core, PacketId::ClientCapability) => {
                if self.state != FilesystemServerState::WaitingForClientCapability {
                    return Ok(Vec::new());
                }
                let resp = CapabilityRequestPdu::decode(body)?;
                // Negotiate the IRP intersection. The General set carries
                // the client's ioCode1; absence of a General set means the
                // client advertised nothing -- treat it as the empty set.
                let client_io_code1 = resp
                    .capabilities
                    .iter()
                    .find_map(|c| match c {
                        CapabilitySet::General(g) => Some(g.io_code1),
                        _ => None,
                    })
                    .unwrap_or(IoCode1::from_bits(0));
                self.negotiated_io_code1 = IoCode1::from_bits(
                    self.config.server_io_code1.bits() & client_io_code1.bits(),
                );
                self.handler.on_client_capabilities(
                    self.negotiated_io_code1,
                    &resp.capabilities,
                );
                self.state = FilesystemServerState::WaitingForDeviceList;
                Ok(Vec::new())
            }

            // Device List Announce -- MS-RDPEFS 2.2.3.1. Per §1.3.1,
            // this is the burst that follows the client's Capability
            // Response. The server replies with a Device Announce
            // Response (2.2.2.1) *per device* -- the result codes come
            // from the application handler.
            (Component::Core, PacketId::DeviceListAnnounce) => {
                // Either we are arriving here for the first time
                // (state == WaitingForDeviceList) or the client has
                // dynamically added devices mid-session (state ==
                // Active). Both are valid per §1.3.2.
                if self.state != FilesystemServerState::WaitingForDeviceList
                    && self.state != FilesystemServerState::Active
                {
                    return Ok(Vec::new());
                }
                let pdu = DeviceListAnnouncePdu::decode(body)?;
                let mut responses = Vec::with_capacity(pdu.devices.len());
                for raw in pdu.devices {
                    let announced = AnnouncedDevice {
                        device_id: raw.device_id,
                        device_type: raw.device_type as u32,
                        preferred_dos_name: raw.dos_name_str().into(),
                        device_data: raw.device_data,
                    };
                    let result_code = self.handler.on_device_announce(&announced);
                    self.announced_devices.push(announced);
                    let resp = DeviceAnnounceResponsePdu {
                        device_id: raw.device_id,
                        result_code,
                    };
                    responses.push(Self::encode_message(
                        Component::Core,
                        PacketId::DeviceReply,
                        &resp,
                    )?);
                }
                self.state = FilesystemServerState::Active;
                Ok(responses)
            }

            // Device I/O Completion -- MS-RDPEFS 2.2.1.5.
            (Component::Core, PacketId::DeviceIoCompletion) => {
                if self.state != FilesystemServerState::Active {
                    return Ok(Vec::new());
                }
                let header = DeviceIoResponse::decode(body)?;
                // The completion id MUST correspond to an in-flight IRP.
                // An unknown id is treated as a protocol violation -- a
                // misbehaving client could otherwise feed us undecodable
                // tail bytes.
                let major = self
                    .inflight
                    .remove(&header.completion_id)
                    .ok_or_else(|| {
                        SvcError::Protocol(alloc::format!(
                            "DeviceIoCompletion for unknown completion_id {}",
                            header.completion_id
                        ))
                    })?;
                let completion = decode_completion_payload(major, body)?;
                self.handler.on_io_completion(
                    header.device_id,
                    header.completion_id,
                    header.io_status,
                    completion,
                );
                Ok(Vec::new())
            }

            _ => {
                // Drop unexpected PDUs silently.
                Ok(Vec::new())
            }
        }
    }
}

// ── IRP emit API ────────────────────────────────────────────────────────────

impl FilesystemServer {
    /// Build a Device Create Request (`DR_CREATE_REQ`,
    /// MS-RDPEFS 2.2.1.4.1) and record an in-flight IRP. Returns the
    /// SvcMessage and the assigned `completion_id` so callers can
    /// correlate against the eventual `IoCompletion::Create`.
    ///
    /// `path` is encoded as UTF-16LE with a null terminator. Errors:
    /// `SvcError::Protocol(_)` if the processor is not yet `Active` or
    /// the in-flight queue is at `MAX_INFLIGHT`.
    pub fn build_create_request(
        &mut self,
        device_id: u32,
        desired_access: u32,
        allocation_size: u64,
        file_attributes: u32,
        shared_access: u32,
        create_disposition: u32,
        create_options: u32,
        path: &str,
    ) -> SvcResult<(SvcMessage, u32)> {
        let completion_id = self.reserve_inflight(MajorFunction::Create)?;
        let header = SharedHeader::new(Component::Core, PacketId::DeviceIoRequest);
        let req = DeviceIoRequest {
            device_id,
            file_id: 0,
            completion_id,
            major_function: MajorFunction::Create,
            minor_function: MinorFunction::None,
        };
        let path_bytes = encode_utf16le_null(path);

        // body = DesiredAccess(4) + AllocationSize(8) + FileAttributes(4)
        //      + SharedAccess(4) + CreateDisposition(4) + CreateOptions(4)
        //      + PathLength(4) + Path
        let body_len = 4 + 8 + 4 + 4 + 4 + 4 + 4 + path_bytes.len();
        let total = header.size() + req.size() + body_len;
        let mut buf = alloc::vec![0u8; total];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor)?;
        req.encode(&mut cursor)?;
        cursor.write_u32_le(desired_access, "Create::DesiredAccess")?;
        cursor.write_u64_le(allocation_size, "Create::AllocationSize")?;
        cursor.write_u32_le(file_attributes, "Create::FileAttributes")?;
        cursor.write_u32_le(shared_access, "Create::SharedAccess")?;
        cursor.write_u32_le(create_disposition, "Create::CreateDisposition")?;
        cursor.write_u32_le(create_options, "Create::CreateOptions")?;
        cursor.write_u32_le(path_bytes.len() as u32, "Create::PathLength")?;
        cursor.write_slice(&path_bytes, "Create::Path")?;
        Ok((SvcMessage::new(buf), completion_id))
    }

    /// Build a Device Close Request (`DR_CLOSE_REQ`, 2.2.1.4.2) for
    /// `file_id` previously returned by an `IoCompletion::Create`.
    pub fn build_close_request(
        &mut self,
        device_id: u32,
        file_id: u32,
    ) -> SvcResult<(SvcMessage, u32)> {
        let completion_id = self.reserve_inflight(MajorFunction::Close)?;
        let header = SharedHeader::new(Component::Core, PacketId::DeviceIoRequest);
        let req = DeviceIoRequest {
            device_id,
            file_id,
            completion_id,
            major_function: MajorFunction::Close,
            minor_function: MinorFunction::None,
        };
        // body = 32 bytes padding (MS-RDPEFS 2.2.1.4.2)
        let total = header.size() + req.size() + 32;
        let mut buf = alloc::vec![0u8; total];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor)?;
        req.encode(&mut cursor)?;
        cursor.write_slice(&[0u8; 32], "Close::Padding")?;
        Ok((SvcMessage::new(buf), completion_id))
    }

    /// Build a Device Read Request (`DR_READ_REQ`, 2.2.1.4.3).
    pub fn build_read_request(
        &mut self,
        device_id: u32,
        file_id: u32,
        length: u32,
        offset: u64,
    ) -> SvcResult<(SvcMessage, u32)> {
        let completion_id = self.reserve_inflight(MajorFunction::Read)?;
        let header = SharedHeader::new(Component::Core, PacketId::DeviceIoRequest);
        let req = DeviceIoRequest {
            device_id,
            file_id,
            completion_id,
            major_function: MajorFunction::Read,
            minor_function: MinorFunction::None,
        };
        // body = Length(4) + Offset(8) + Padding(20)
        let total = header.size() + req.size() + 4 + 8 + 20;
        let mut buf = alloc::vec![0u8; total];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor)?;
        req.encode(&mut cursor)?;
        cursor.write_u32_le(length, "Read::Length")?;
        cursor.write_u64_le(offset, "Read::Offset")?;
        cursor.write_slice(&[0u8; 20], "Read::Padding")?;
        Ok((SvcMessage::new(buf), completion_id))
    }

    /// Build a Device Write Request (`DR_WRITE_REQ`, 2.2.1.4.4).
    pub fn build_write_request(
        &mut self,
        device_id: u32,
        file_id: u32,
        offset: u64,
        data: &[u8],
    ) -> SvcResult<(SvcMessage, u32)> {
        let completion_id = self.reserve_inflight(MajorFunction::Write)?;
        let header = SharedHeader::new(Component::Core, PacketId::DeviceIoRequest);
        let req = DeviceIoRequest {
            device_id,
            file_id,
            completion_id,
            major_function: MajorFunction::Write,
            minor_function: MinorFunction::None,
        };
        // body = Length(4) + Offset(8) + Padding(20) + WriteData
        let total = header.size() + req.size() + 4 + 8 + 20 + data.len();
        let mut buf = alloc::vec![0u8; total];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor)?;
        req.encode(&mut cursor)?;
        cursor.write_u32_le(data.len() as u32, "Write::Length")?;
        cursor.write_u64_le(offset, "Write::Offset")?;
        cursor.write_slice(&[0u8; 20], "Write::Padding")?;
        cursor.write_slice(data, "Write::WriteData")?;
        Ok((SvcMessage::new(buf), completion_id))
    }

    /// Reserve a completion id, gating on the active state and the
    /// in-flight cap.
    fn reserve_inflight(&mut self, major: MajorFunction) -> SvcResult<u32> {
        if self.state != FilesystemServerState::Active {
            return Err(SvcError::Protocol(alloc::format!(
                "FilesystemServer cannot emit IRP -- not yet Active (state={:?})",
                self.state
            )));
        }
        if self.inflight.len() >= MAX_INFLIGHT {
            return Err(SvcError::Protocol(alloc::format!(
                "FilesystemServer in-flight cap reached ({} IRPs without completion)",
                MAX_INFLIGHT
            )));
        }
        let id = self.next_completion_id;
        self.next_completion_id = self.next_completion_id.wrapping_add(1);
        self.inflight.insert(id, major);
        Ok(id)
    }
}

/// Decode the per-major payload that follows the 12-byte
/// `DR_DEVICE_IOCOMPLETION` header. The major-function dispatch is
/// resolved from the in-flight queue at the call site.
fn decode_completion_payload(
    major: MajorFunction,
    src: &mut ReadCursor<'_>,
) -> SvcResult<IoCompletion> {
    match major {
        MajorFunction::Create => {
            // FileId(4) + Information(1) -- MS-RDPEFS 2.2.1.5.1
            let file_id = src.read_u32_le("CreateRsp::FileId")?;
            let information = src.read_u8("CreateRsp::Information")?;
            Ok(IoCompletion::Create {
                file_id,
                information,
            })
        }
        MajorFunction::Close => {
            // 4 bytes padding -- MS-RDPEFS 2.2.1.5.2
            src.skip(4, "CloseRsp::Padding")?;
            Ok(IoCompletion::Close)
        }
        MajorFunction::Read => {
            // Length(4) + ReadData -- MS-RDPEFS 2.2.1.5.3
            let length = src.read_u32_le("ReadRsp::Length")?;
            // Bound the response size against the wire-truncation budget
            // the cursor already enforces; a malicious value of u32::MAX
            // will fail at read_slice without allocating.
            let data = src
                .read_slice(length as usize, "ReadRsp::ReadData")?
                .to_vec();
            Ok(IoCompletion::Read { data })
        }
        MajorFunction::Write => {
            // Length(4) + Padding(1) -- MS-RDPEFS 2.2.1.5.4
            let bytes_written = src.read_u32_le("WriteRsp::Length")?;
            // Pad byte is optional -- some clients omit it. Tolerate
            // both forms by only consuming if present.
            let _ = src.read_u8("WriteRsp::Padding").ok();
            Ok(IoCompletion::Write { bytes_written })
        }
        // The first scope only supports CREATE/CLOSE/READ/WRITE; the
        // other majors aren't reachable until S3 grows them.
        other => Err(SvcError::Protocol(alloc::format!(
            "DeviceIoCompletion for unsupported major {:?}",
            other
        ))),
    }
}

/// UTF-16LE null-terminated encoder for path fields (MS-RDPEFS uses
/// PathLength + Unicode path with explicit null terminator).
fn encode_utf16le_null(s: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity((s.len() + 1) * 2);
    for code_unit in s.encode_utf16() {
        buf.extend_from_slice(&code_unit.to_le_bytes());
    }
    buf.extend_from_slice(&[0x00, 0x00]);
    buf
}

impl SvcProcessor for FilesystemServer {
    fn channel_name(&self) -> ChannelName {
        RDPDR
    }

    fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
        if self.state != FilesystemServerState::NotStarted {
            return Ok(Vec::new());
        }
        self.state = FilesystemServerState::WaitingForClientAnnounce;
        Ok(alloc::vec![self.build_server_announce()?])
    }

    fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
        let mut cursor = ReadCursor::new(payload);
        let header = SharedHeader::decode(&mut cursor)?;
        self.handle_pdu(&header, &mut cursor)
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }
}

impl SvcServerProcessor for FilesystemServer {}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::pdu::device::{DeviceAnnounce, DeviceType};
    use crate::pdu::init::VersionPdu;

    #[derive(Default, Debug)]
    struct HandlerState {
        names: Vec<(String, bool)>,
        cap_calls: Vec<(IoCode1, Vec<CapabilitySet>)>,
        device_announces: Vec<AnnouncedDevice>,
        completions: Vec<(u32, u32, u32, IoCompletion)>,
    }

    struct MockHandler {
        state: Arc<Mutex<HandlerState>>,
        /// Map device_id -> NTSTATUS to return on announce. Default
        /// (None) accepts every device with STATUS_SUCCESS.
        device_announce_overrides: Vec<(u32, u32)>,
    }

    impl MockHandler {
        fn new() -> (Self, Arc<Mutex<HandlerState>>) {
            let state = Arc::new(Mutex::new(HandlerState::default()));
            (
                Self {
                    state: state.clone(),
                    device_announce_overrides: Vec::new(),
                },
                state,
            )
        }
    }

    impl RdpServerFilesystemHandler for MockHandler {
        fn on_client_name(&mut self, computer_name: &str, unicode: bool) {
            self.state
                .lock()
                .unwrap()
                .names
                .push((computer_name.into(), unicode));
        }

        fn on_client_capabilities(
            &mut self,
            negotiated_io_code1: IoCode1,
            client_capability_sets: &[CapabilitySet],
        ) {
            self.state
                .lock()
                .unwrap()
                .cap_calls
                .push((negotiated_io_code1, client_capability_sets.to_vec()));
        }

        fn on_device_announce(&mut self, device: &AnnouncedDevice) -> u32 {
            self.state.lock().unwrap().device_announces.push(device.clone());
            self.device_announce_overrides
                .iter()
                .find(|(id, _)| *id == device.device_id)
                .map(|(_, status)| *status)
                .unwrap_or(STATUS_SUCCESS)
        }

        fn on_io_completion(
            &mut self,
            device_id: u32,
            completion_id: u32,
            io_status: u32,
            completion: IoCompletion,
        ) {
            self.state.lock().unwrap().completions.push((
                device_id,
                completion_id,
                io_status,
                completion,
            ));
        }
    }

    fn new_server() -> (FilesystemServer, Arc<Mutex<HandlerState>>) {
        let (handler, state) = MockHandler::new();
        (FilesystemServer::new(Box::new(handler)), state)
    }

    fn encode_with_header<T: Encode>(packet_id: PacketId, body: &T) -> Vec<u8> {
        let header = SharedHeader::new(Component::Core, packet_id);
        let mut buf = alloc::vec![0u8; header.size() + body.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor).unwrap();
        body.encode(&mut cursor).unwrap();
        buf
    }

    fn decode_header(msg: &SvcMessage) -> SharedHeader {
        let mut cursor = ReadCursor::new(&msg.data);
        SharedHeader::decode(&mut cursor).unwrap()
    }

    #[test]
    fn start_emits_server_announce() {
        let (mut server, _state) = new_server();
        let msgs = server.start().unwrap();
        assert_eq!(msgs.len(), 1, "expected single Server Announce");

        let header = decode_header(&msgs[0]);
        assert_eq!(header.component, Component::Core);
        assert_eq!(header.packet_id, PacketId::ServerAnnounce);

        // VersionPdu body follows the 4-byte shared header.
        let mut cursor = ReadCursor::new(&msgs[0].data);
        let _ = SharedHeader::decode(&mut cursor).unwrap();
        let body = ServerAnnounceRequest::decode(&mut cursor).unwrap();
        assert_eq!(body.version_major, 0x0001);
        assert_eq!(body.version_minor, VERSION_MINOR_DEFAULT);
        assert_eq!(body.client_id, 1);
    }

    #[test]
    fn start_is_idempotent() {
        let (mut server, _state) = new_server();
        let first = server.start().unwrap();
        assert_eq!(first.len(), 1);
        let second = server.start().unwrap();
        assert!(second.is_empty(), "second start() must be a no-op");
    }

    #[test]
    fn version_minor_negotiates_min_server_client() {
        let (handler, _state) = MockHandler::new();
        let mut server = FilesystemServer::with_config(
            Box::new(handler),
            FilesystemServerConfig {
                initial_client_id: 7,
                max_version_minor: 0x000C,
                ..FilesystemServerConfig::new()
            },
        );
        server.start().unwrap();

        // Client claims an older minor version 0x000A.
        let reply = ClientAnnounceReply {
            version_major: 0x0001,
            version_minor: 0x000A,
            client_id: 0x4242_4242,
        };
        let resp = server
            .process(&encode_with_header(PacketId::ClientIdConfirm, &reply))
            .unwrap();
        assert!(resp.is_empty(), "no immediate emit in S1 phase");

        assert_eq!(server.version_minor(), 0x000A, "min(server=0x0C, client=0x0A)");
        assert_eq!(server.client_id(), 0x4242_4242, "client may rewrite the id");
    }

    #[test]
    fn version_minor_caps_at_server_max() {
        let (handler, _state) = MockHandler::new();
        let mut server = FilesystemServer::with_config(
            Box::new(handler),
            FilesystemServerConfig {
                initial_client_id: 1,
                max_version_minor: 0x000A,
                ..FilesystemServerConfig::new()
            },
        );
        server.start().unwrap();

        // Client claims a newer minor version; server caps at its max.
        let reply = ClientAnnounceReply {
            version_major: 0x0001,
            version_minor: 0x000C,
            client_id: 1,
        };
        server
            .process(&encode_with_header(PacketId::ClientIdConfirm, &reply))
            .unwrap();

        assert_eq!(server.version_minor(), 0x000A);
    }

    #[test]
    fn client_name_unicode_dispatched_to_handler() {
        let (mut server, state) = new_server();
        server.start().unwrap();

        let reply = ClientAnnounceReply {
            version_major: 0x0001,
            version_minor: 0x000C,
            client_id: 1,
        };
        server
            .process(&encode_with_header(PacketId::ClientIdConfirm, &reply))
            .unwrap();

        let name = ClientNameRequest {
            unicode: true,
            computer_name: String::from("DESKTOP-RDP"),
        };
        let resp = server
            .process(&encode_with_header(PacketId::ClientName, &name))
            .unwrap();
        // S2: ClientName triggers Server Capability + Client ID Confirm.
        assert_eq!(resp.len(), 2);

        let s = state.lock().unwrap();
        assert_eq!(s.names.len(), 1);
        assert_eq!(s.names[0].0, "DESKTOP-RDP");
        assert!(s.names[0].1);
        drop(s);
        assert_eq!(server.client_computer_name(), Some("DESKTOP-RDP"));
    }

    #[test]
    fn client_name_ascii_dispatched_to_handler() {
        let (mut server, state) = new_server();
        server.start().unwrap();
        server
            .process(&encode_with_header(
                PacketId::ClientIdConfirm,
                &ClientAnnounceReply {
                    version_major: 0x0001,
                    version_minor: 0x000C,
                    client_id: 1,
                },
            ))
            .unwrap();

        let name = ClientNameRequest {
            unicode: false,
            computer_name: String::from("OLDPC"),
        };
        let resp = server
            .process(&encode_with_header(PacketId::ClientName, &name))
            .unwrap();
        assert_eq!(resp.len(), 2, "S2 burst follows ClientName");

        let s = state.lock().unwrap();
        assert_eq!(s.names[0].0, "OLDPC");
        assert!(!s.names[0].1, "ASCII flag preserved");
    }

    #[test]
    fn client_name_before_announce_reply_dropped() {
        // PDUs received in the wrong state must be silently dropped --
        // never emit, never reach the handler.
        let (mut server, state) = new_server();
        server.start().unwrap();

        let name = ClientNameRequest {
            unicode: true,
            computer_name: String::from("EARLY"),
        };
        let resp = server
            .process(&encode_with_header(PacketId::ClientName, &name))
            .unwrap();
        assert!(resp.is_empty());
        assert!(state.lock().unwrap().names.is_empty());
        assert_eq!(server.client_computer_name(), None);
    }

    #[test]
    fn duplicate_announce_reply_dropped() {
        let (mut server, _state) = new_server();
        server.start().unwrap();
        let reply = ClientAnnounceReply {
            version_major: 0x0001,
            version_minor: 0x000A,
            client_id: 0xAAAA,
        };
        server
            .process(&encode_with_header(PacketId::ClientIdConfirm, &reply))
            .unwrap();

        // Second reply MUST be a no-op (state has advanced).
        let second = ClientAnnounceReply {
            version_major: 0x0001,
            version_minor: 0x0001,
            client_id: 0xBBBB,
        };
        server
            .process(&encode_with_header(PacketId::ClientIdConfirm, &second))
            .unwrap();
        assert_eq!(server.version_minor(), 0x000A, "first reply still wins");
        assert_eq!(server.client_id(), 0xAAAA);
    }

    #[test]
    fn unrelated_packet_id_pre_init_dropped() {
        // Anything other than the expected PacketId is dropped (pre-S2).
        let (mut server, state) = new_server();
        server.start().unwrap();

        // Send a DeviceListAnnounce body shape (will arrive in S3) -- must
        // be dropped because the state machine hasn't reached the cap-resp
        // step yet.
        let bogus = VersionPdu {
            version_major: 0,
            version_minor: 0,
            client_id: 0,
        };
        let resp = server
            .process(&encode_with_header(PacketId::DeviceListAnnounce, &bogus))
            .unwrap();
        assert!(resp.is_empty());
        assert!(state.lock().unwrap().names.is_empty());
    }

    // ── S2 ── Server Capability burst + Client Capability response ──

    fn drive_to_capability_phase(server: &mut FilesystemServer) -> Vec<SvcMessage> {
        server.start().unwrap();
        server
            .process(&encode_with_header(
                PacketId::ClientIdConfirm,
                &ClientAnnounceReply {
                    version_major: 0x0001,
                    version_minor: 0x000C,
                    client_id: 1,
                },
            ))
            .unwrap();
        server
            .process(&encode_with_header(
                PacketId::ClientName,
                &ClientNameRequest {
                    unicode: true,
                    computer_name: String::from("PC"),
                },
            ))
            .unwrap()
    }

    #[test]
    fn client_name_emits_capability_request_then_clientid_confirm() {
        let (mut server, _state) = new_server();
        let burst = drive_to_capability_phase(&mut server);
        assert_eq!(burst.len(), 2);

        let h0 = decode_header(&burst[0]);
        assert_eq!(h0.component, Component::Core);
        assert_eq!(
            h0.packet_id,
            PacketId::ServerCapability,
            "Capability Request emits first"
        );

        let h1 = decode_header(&burst[1]);
        assert_eq!(h1.packet_id, PacketId::ClientIdConfirm);

        // Capability Request body parses cleanly and carries the
        // configured ioCode1 plus a Drive cap entry.
        let mut cursor = ReadCursor::new(&burst[0].data);
        let _ = SharedHeader::decode(&mut cursor).unwrap();
        let caps = CapabilityRequestPdu::decode(&mut cursor).unwrap();
        let general = caps.capabilities.iter().find_map(|c| match c {
            CapabilitySet::General(g) => Some(g.clone()),
            _ => None,
        });
        let general = general.expect("server emits a General cap set");
        assert_eq!(
            general.io_code1,
            IoCode1::RDPDR_IRP_MJ_CREATE
                .union(IoCode1::RDPDR_IRP_MJ_CLOSE)
                .union(IoCode1::RDPDR_IRP_MJ_READ)
                .union(IoCode1::RDPDR_IRP_MJ_WRITE)
        );
        assert!(caps
            .capabilities
            .iter()
            .any(|c| matches!(c, CapabilitySet::Drive { .. })));
    }

    #[test]
    fn capability_request_uses_negotiated_minor_version() {
        // Negotiated minor (the min of server/client) must propagate
        // into the General cap's protocolMinorVersion field.
        let (handler, _state) = MockHandler::new();
        let mut server = FilesystemServer::with_config(
            Box::new(handler),
            FilesystemServerConfig {
                initial_client_id: 1,
                max_version_minor: 0x000C,
                ..FilesystemServerConfig::new()
            },
        );
        server.start().unwrap();
        server
            .process(&encode_with_header(
                PacketId::ClientIdConfirm,
                &ClientAnnounceReply {
                    version_major: 0x0001,
                    version_minor: 0x000A, // forces negotiation down
                    client_id: 1,
                },
            ))
            .unwrap();
        let burst = server
            .process(&encode_with_header(
                PacketId::ClientName,
                &ClientNameRequest {
                    unicode: true,
                    computer_name: String::from("PC"),
                },
            ))
            .unwrap();

        let mut cursor = ReadCursor::new(&burst[0].data);
        let _ = SharedHeader::decode(&mut cursor).unwrap();
        let caps = CapabilityRequestPdu::decode(&mut cursor).unwrap();
        let general = caps.capabilities.iter().find_map(|c| match c {
            CapabilitySet::General(g) => Some(g.clone()),
            _ => None,
        });
        assert_eq!(general.unwrap().protocol_minor_version, 0x000A);
    }

    #[test]
    fn client_capability_response_negotiates_io_code_intersection() {
        let (mut server, state) = new_server();
        drive_to_capability_phase(&mut server);

        // Client supports CREATE+READ+QUERY_INFO; server advertises
        // CREATE+CLOSE+READ+WRITE -> intersection = CREATE+READ.
        let client_caps = CapabilityRequestPdu::new(alloc::vec![
            CapabilitySet::General(GeneralCapabilitySet {
                os_type: 0,
                os_version: 0,
                protocol_major_version: RDPDR_MAJOR_RDP_VERSION,
                protocol_minor_version: 0x000C,
                io_code1: IoCode1::RDPDR_IRP_MJ_CREATE
                    .union(IoCode1::RDPDR_IRP_MJ_READ)
                    .union(IoCode1::RDPDR_IRP_MJ_QUERY_INFORMATION),
                extended_pdu: ExtendedPdu::RDPDR_USER_LOGGEDON_PDU,
                extra_flags1: ExtraFlags1::NONE,
                special_type_device_cap: Some(0),
            }),
            CapabilitySet::Drive {
                version: GENERAL_CAPABILITY_VERSION_02,
            },
        ]);
        let resp = server
            .process(&encode_with_header(PacketId::ClientCapability, &client_caps))
            .unwrap();
        assert!(resp.is_empty(), "S2 has no immediate emit on cap response");

        let expected = IoCode1::RDPDR_IRP_MJ_CREATE.union(IoCode1::RDPDR_IRP_MJ_READ);
        assert_eq!(server.negotiated_io_code1(), expected);

        let s = state.lock().unwrap();
        assert_eq!(s.cap_calls.len(), 1);
        assert_eq!(s.cap_calls[0].0, expected);
        // Handler also receives the raw cap list -- contains General + Drive.
        assert!(matches!(s.cap_calls[0].1[0], CapabilitySet::General(_)));
        assert!(matches!(s.cap_calls[0].1[1], CapabilitySet::Drive { .. }));
    }

    #[test]
    fn client_capability_response_without_general_set_zeroes_intersection() {
        // MS-RDPEFS 2.2.2.8 mandates a General set, but a buggy client
        // could omit it. Treat absence as the empty set rather than
        // erroring -- matches the cliprdr 'no Caps PDU' degradation.
        let (mut server, _state) = new_server();
        drive_to_capability_phase(&mut server);

        let client_caps = CapabilityRequestPdu::new(alloc::vec![CapabilitySet::Drive {
            version: GENERAL_CAPABILITY_VERSION_02,
        }]);
        server
            .process(&encode_with_header(PacketId::ClientCapability, &client_caps))
            .unwrap();
        assert_eq!(server.negotiated_io_code1(), IoCode1::from_bits(0));
    }

    #[test]
    fn client_capability_pre_state_dropped() {
        // ClientCapability before ClientName must be silently dropped.
        let (mut server, state) = new_server();
        server.start().unwrap();
        server
            .process(&encode_with_header(
                PacketId::ClientIdConfirm,
                &ClientAnnounceReply {
                    version_major: 0x0001,
                    version_minor: 0x000C,
                    client_id: 1,
                },
            ))
            .unwrap();
        // Skip ClientName entirely -> still in WaitingForClientName.
        let client_caps = CapabilityRequestPdu::new(alloc::vec![]);
        let resp = server
            .process(&encode_with_header(PacketId::ClientCapability, &client_caps))
            .unwrap();
        assert!(resp.is_empty());
        assert!(state.lock().unwrap().cap_calls.is_empty());
        assert_eq!(server.negotiated_io_code1(), IoCode1::from_bits(0));
    }

    #[test]
    fn duplicate_client_capability_dropped() {
        let (mut server, state) = new_server();
        drive_to_capability_phase(&mut server);

        let first = CapabilityRequestPdu::new(alloc::vec![CapabilitySet::General(
            GeneralCapabilitySet {
                os_type: 0,
                os_version: 0,
                protocol_major_version: RDPDR_MAJOR_RDP_VERSION,
                protocol_minor_version: 0x000C,
                io_code1: IoCode1::RDPDR_IRP_MJ_CREATE,
                extended_pdu: ExtendedPdu::RDPDR_USER_LOGGEDON_PDU,
                extra_flags1: ExtraFlags1::NONE,
                special_type_device_cap: Some(0),
            },
        )]);
        server
            .process(&encode_with_header(PacketId::ClientCapability, &first))
            .unwrap();

        // Second response: server must NOT re-dispatch (state advanced).
        let second = CapabilityRequestPdu::new(alloc::vec![CapabilitySet::General(
            GeneralCapabilitySet {
                os_type: 0,
                os_version: 0,
                protocol_major_version: RDPDR_MAJOR_RDP_VERSION,
                protocol_minor_version: 0x000C,
                io_code1: IoCode1::RDPDR_IRP_MJ_WRITE,
                extended_pdu: ExtendedPdu::RDPDR_USER_LOGGEDON_PDU,
                extra_flags1: ExtraFlags1::NONE,
                special_type_device_cap: Some(0),
            },
        )]);
        server
            .process(&encode_with_header(PacketId::ClientCapability, &second))
            .unwrap();

        let s = state.lock().unwrap();
        assert_eq!(s.cap_calls.len(), 1, "second cap response is dropped");
        assert_eq!(s.cap_calls[0].0, IoCode1::RDPDR_IRP_MJ_CREATE);
    }

    // ── S3 ── Device list, IRP emit, IO completion ──────────────────────

    fn drive_to_active(server: &mut FilesystemServer) {
        drive_to_capability_phase(server);
        let client_caps = CapabilityRequestPdu::new(alloc::vec![CapabilitySet::General(
            GeneralCapabilitySet {
                os_type: 0,
                os_version: 0,
                protocol_major_version: RDPDR_MAJOR_RDP_VERSION,
                protocol_minor_version: 0x000C,
                io_code1: IoCode1::RDPDR_IRP_MJ_CREATE
                    .union(IoCode1::RDPDR_IRP_MJ_CLOSE)
                    .union(IoCode1::RDPDR_IRP_MJ_READ)
                    .union(IoCode1::RDPDR_IRP_MJ_WRITE),
                extended_pdu: ExtendedPdu::RDPDR_USER_LOGGEDON_PDU,
                extra_flags1: ExtraFlags1::NONE,
                special_type_device_cap: Some(0),
            },
        )]);
        server
            .process(&encode_with_header(PacketId::ClientCapability, &client_caps))
            .unwrap();
    }

    fn announce_one_drive(server: &mut FilesystemServer) -> Vec<SvcMessage> {
        let pdu = DeviceListAnnouncePdu {
            devices: alloc::vec![DeviceAnnounce::filesystem(7, "C:", Some("Local Disk"))],
        };
        server
            .process(&encode_with_header(PacketId::DeviceListAnnounce, &pdu))
            .unwrap()
    }

    #[test]
    fn device_list_announce_emits_per_device_response_and_advances_active() {
        let (mut server, state) = new_server();
        drive_to_active(&mut server);
        assert!(!server.is_active(), "server should still be in WaitingForDeviceList");

        let pdu = DeviceListAnnouncePdu {
            devices: alloc::vec![
                DeviceAnnounce::filesystem(1, "C:", None),
                DeviceAnnounce::filesystem(2, "D:", Some("Data")),
            ],
        };
        let resp = server
            .process(&encode_with_header(PacketId::DeviceListAnnounce, &pdu))
            .unwrap();
        assert_eq!(resp.len(), 2, "one DeviceReply per announced device");

        for (idx, msg) in resp.iter().enumerate() {
            let h = decode_header(msg);
            assert_eq!(h.packet_id, PacketId::DeviceReply);
            let mut cursor = ReadCursor::new(&msg.data);
            let _ = SharedHeader::decode(&mut cursor).unwrap();
            let body = DeviceAnnounceResponsePdu::decode(&mut cursor).unwrap();
            assert_eq!(body.device_id, (idx as u32) + 1);
            assert_eq!(body.result_code, STATUS_SUCCESS);
        }

        assert!(server.is_active());
        let s = state.lock().unwrap();
        assert_eq!(s.device_announces.len(), 2);
        assert_eq!(s.device_announces[0].preferred_dos_name, "C:");
        assert_eq!(s.device_announces[1].preferred_dos_name, "D:");
        // Drive 2 carries UTF-16LE "Data\0" device data.
        assert!(!s.device_announces[1].device_data.is_empty());
    }

    #[test]
    fn handler_can_reject_device_with_nonzero_ntstatus() {
        let (handler_inner, state) = MockHandler::new();
        let mut handler = handler_inner;
        handler.device_announce_overrides.push((9, 0xC000_0022)); // STATUS_ACCESS_DENIED
        let mut server = FilesystemServer::new(Box::new(handler));
        drive_to_active(&mut server);

        let pdu = DeviceListAnnouncePdu {
            devices: alloc::vec![
                DeviceAnnounce::filesystem(8, "X:", None), // accepted
                DeviceAnnounce::filesystem(9, "Y:", None), // rejected
            ],
        };
        let resp = server
            .process(&encode_with_header(PacketId::DeviceListAnnounce, &pdu))
            .unwrap();
        assert_eq!(resp.len(), 2);

        let mut cursor1 = ReadCursor::new(&resp[1].data);
        let _ = SharedHeader::decode(&mut cursor1).unwrap();
        let body1 = DeviceAnnounceResponsePdu::decode(&mut cursor1).unwrap();
        assert_eq!(body1.result_code, 0xC000_0022);

        // Both still tracked locally so emit APIs can still address them.
        assert_eq!(server.announced_devices().len(), 2);
        let _ = state; // suppress unused
    }

    #[test]
    fn dynamic_device_announce_after_active_appends() {
        // MS-RDPEFS 1.3.2: client may add devices mid-session. Server
        // must continue to issue per-device responses without leaving
        // the Active state.
        let (mut server, _state) = new_server();
        drive_to_active(&mut server);
        let _ = announce_one_drive(&mut server);
        assert!(server.is_active());
        assert_eq!(server.announced_devices().len(), 1);

        let pdu2 = DeviceListAnnouncePdu {
            devices: alloc::vec![DeviceAnnounce::printer(11, "PRN1", alloc::vec![0xAA, 0xBB])],
        };
        let resp = server
            .process(&encode_with_header(PacketId::DeviceListAnnounce, &pdu2))
            .unwrap();
        assert_eq!(resp.len(), 1);
        assert_eq!(server.announced_devices().len(), 2);
        assert_eq!(server.announced_devices()[1].device_type, DeviceType::Printer as u32);
    }

    #[test]
    fn irp_emit_blocked_before_active() {
        let (mut server, _state) = new_server();
        drive_to_active(&mut server);
        // Still not Active -- no DeviceList yet.
        let res = server.build_create_request(1, 0, 0, 0, 0, 0, 0, "\\");
        assert!(matches!(res, Err(SvcError::Protocol(_))));
    }

    #[test]
    fn irp_create_emit_round_trips_with_completion() {
        let (mut server, state) = new_server();
        drive_to_active(&mut server);
        announce_one_drive(&mut server);

        let (msg, cid) = server
            .build_create_request(7, 0x8000_0001, 0, 0, 0x0000_0007, 0x0000_0001, 0x0000_0021, "\\")
            .unwrap();
        assert_eq!(cid, 0, "first completion id is 0");
        assert_eq!(server.inflight_count(), 1);

        let h = decode_header(&msg);
        assert_eq!(h.packet_id, PacketId::DeviceIoRequest);
        // Body = DeviceIoRequest(20) + per-major fields.
        // The wire format is what the existing client-side decoder
        // expects, so use that as the round-trip oracle.
        let mut cursor = ReadCursor::new(&msg.data);
        let _ = SharedHeader::decode(&mut cursor).unwrap();
        let req = DeviceIoRequest::decode(&mut cursor).unwrap();
        assert_eq!(req.device_id, 7);
        assert_eq!(req.completion_id, 0);
        assert_eq!(req.major_function, MajorFunction::Create);
        let irp = crate::pdu::irp::IrpRequest::decode_body(
            req.major_function,
            req.minor_function,
            &mut cursor,
        )
        .unwrap();
        match irp {
            crate::pdu::irp::IrpRequest::Create(c) => {
                assert_eq!(c.desired_access, 0x8000_0001);
                assert_eq!(c.create_disposition, 0x0000_0001);
                assert_eq!(c.create_options, 0x0000_0021);
                assert_eq!(c.path, "\\");
            }
            _ => panic!("expected Create"),
        }

        // Inject the matching completion: FileId=42, Information=FILE_OPENED.
        let mut payload = Vec::new();
        let resp = DeviceIoResponse {
            device_id: 7,
            completion_id: cid,
            io_status: STATUS_SUCCESS,
        };
        let header = SharedHeader::new(Component::Core, PacketId::DeviceIoCompletion);
        let mut buf = alloc::vec![0u8; header.size() + resp.size() + 5];
        let mut wc = WriteCursor::new(&mut buf);
        header.encode(&mut wc).unwrap();
        resp.encode(&mut wc).unwrap();
        wc.write_u32_le(42, "FileId").unwrap();
        wc.write_u8(0x01, "Information").unwrap();
        payload.extend_from_slice(&buf);

        let r = server.process(&payload).unwrap();
        assert!(r.is_empty(), "completion produces no outbound");
        assert_eq!(server.inflight_count(), 0, "completion clears inflight");

        let s = state.lock().unwrap();
        assert_eq!(s.completions.len(), 1);
        assert_eq!(s.completions[0].0, 7);
        assert_eq!(s.completions[0].1, 0);
        assert_eq!(s.completions[0].2, STATUS_SUCCESS);
        match &s.completions[0].3 {
            IoCompletion::Create { file_id, information } => {
                assert_eq!(*file_id, 42);
                assert_eq!(*information, 0x01);
            }
            other => panic!("expected Create, got {:?}", other),
        }
    }

    #[test]
    fn irp_read_write_close_round_trip_completions() {
        let (mut server, state) = new_server();
        drive_to_active(&mut server);
        announce_one_drive(&mut server);

        // Read 4096 bytes at offset 0.
        let (_msg, cid_r) = server.build_read_request(7, 0x42, 4096, 0).unwrap();
        // Write 5 bytes "hello" at offset 100.
        let (_msg, cid_w) = server
            .build_write_request(7, 0x42, 100, b"hello")
            .unwrap();
        // Close fid 0x42.
        let (_msg, cid_c) = server.build_close_request(7, 0x42).unwrap();
        assert_eq!(server.inflight_count(), 3);

        // Inject Read completion with 3 bytes payload "abc".
        let read_payload = make_completion(7, cid_r, STATUS_SUCCESS, |c| {
            c.write_u32_le(3, "Length")?;
            c.write_slice(b"abc", "ReadData")?;
            Ok(())
        });
        server.process(&read_payload).unwrap();

        // Write completion: 5 bytes written.
        let write_payload = make_completion(7, cid_w, STATUS_SUCCESS, |c| {
            c.write_u32_le(5, "Length")?;
            c.write_u8(0, "Padding")?;
            Ok(())
        });
        server.process(&write_payload).unwrap();

        // Close completion: 4 bytes padding.
        let close_payload = make_completion(7, cid_c, STATUS_SUCCESS, |c| {
            c.write_slice(&[0u8; 4], "Padding")?;
            Ok(())
        });
        server.process(&close_payload).unwrap();

        assert_eq!(server.inflight_count(), 0);
        let s = state.lock().unwrap();
        assert_eq!(s.completions.len(), 3);
        // Order: read, write, close (insertion order).
        match &s.completions[0].3 {
            IoCompletion::Read { data } => assert_eq!(data, b"abc"),
            _ => panic!(),
        }
        match &s.completions[1].3 {
            IoCompletion::Write { bytes_written } => assert_eq!(*bytes_written, 5),
            _ => panic!(),
        }
        assert!(matches!(s.completions[2].3, IoCompletion::Close));
    }

    /// Helper: build a DeviceIoCompletion frame with caller-supplied
    /// per-major payload writer.
    fn make_completion(
        device_id: u32,
        completion_id: u32,
        io_status: u32,
        write_payload: impl FnOnce(&mut WriteCursor<'_>) -> justrdp_core::EncodeResult<()>,
    ) -> Vec<u8> {
        let header = SharedHeader::new(Component::Core, PacketId::DeviceIoCompletion);
        let resp = DeviceIoResponse {
            device_id,
            completion_id,
            io_status,
        };
        let mut buf = alloc::vec![0u8; header.size() + resp.size() + 64];
        let mut wc = WriteCursor::new(&mut buf);
        header.encode(&mut wc).unwrap();
        resp.encode(&mut wc).unwrap();
        let before = wc.pos();
        write_payload(&mut wc).unwrap();
        let total = before + (wc.pos() - before);
        buf.truncate(total);
        buf
    }

    #[test]
    fn unknown_completion_id_rejected() {
        let (mut server, _state) = new_server();
        drive_to_active(&mut server);
        announce_one_drive(&mut server);

        // No IRP emitted -> id 0xDEADBEEF is unknown.
        let payload = make_completion(7, 0xDEADBEEF, STATUS_SUCCESS, |c| {
            c.write_u32_le(0, "Length")?;
            Ok(())
        });
        let res = server.process(&payload);
        assert!(matches!(res, Err(SvcError::Protocol(_))));
    }

    #[test]
    fn completion_id_increments_per_emit() {
        let (mut server, _state) = new_server();
        drive_to_active(&mut server);
        announce_one_drive(&mut server);

        let (_, c0) = server.build_create_request(7, 0, 0, 0, 0, 0, 0, "\\").unwrap();
        let (_, c1) = server.build_close_request(7, 0).unwrap();
        let (_, c2) = server.build_read_request(7, 0, 1, 0).unwrap();
        assert_eq!((c0, c1, c2), (0, 1, 2));
    }

    #[test]
    fn device_list_pre_active_dropped() {
        // DeviceListAnnounce arriving before the cap response phase
        // (state == WaitingForClientCapability) must be silently dropped.
        let (mut server, state) = new_server();
        drive_to_capability_phase(&mut server);
        // Still in WaitingForClientCapability.
        let pdu = DeviceListAnnouncePdu {
            devices: alloc::vec![DeviceAnnounce::filesystem(1, "C:", None)],
        };
        let resp = server
            .process(&encode_with_header(PacketId::DeviceListAnnounce, &pdu))
            .unwrap();
        assert!(resp.is_empty());
        assert!(state.lock().unwrap().device_announces.is_empty());
        assert!(!server.is_active());
    }
}
