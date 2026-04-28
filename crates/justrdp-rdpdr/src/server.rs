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
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_svc::{
    ChannelName, CompressionCondition, SvcMessage, SvcProcessor, SvcResult, SvcServerProcessor,
    RDPDR,
};

use crate::pdu::header::{Component, PacketId, SharedHeader};
use crate::pdu::init::{ClientAnnounceReply, ClientNameRequest, ServerAnnounceRequest};

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
    /// Capability negotiation phase. S2 will land Server Capability
    /// emit and Client Capability decode here.
    WaitingForClientCapability,
}

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
}

impl FilesystemServerConfig {
    /// Default config: clientId=1, max minor version=0x000C
    /// (Windows Server 2012 / latest published spec level).
    pub fn new() -> Self {
        Self {
            initial_client_id: 1,
            max_version_minor: VERSION_MINOR_DEFAULT,
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
/// S1 only exposes the Client Name notification -- capability,
/// device-announce, and IO-completion callbacks land in S2/S3. The
/// trait is `Send` so it can live across async boundaries.
pub trait RdpServerFilesystemHandler: Send {
    /// Client identified itself with a Client Name Request PDU
    /// (MS-RDPEFS 2.2.2.4). `computer_name` is the decoded ASCII or
    /// UTF-16LE name; `unicode` mirrors the wire UnicodeFlag for
    /// callers that need to know which form was used.
    fn on_client_name(&mut self, _computer_name: &str, _unicode: bool) {}
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
                // S2 will emit Server Core Capability Request + Client ID
                // Confirm here; for S1 we just settle into the wait state.
                Ok(Vec::new())
            }

            _ => {
                // Drop unexpected / S2+ PDUs silently. They will be wired
                // into handle_pdu as later sub-stages land.
                Ok(Vec::new())
            }
        }
    }
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

    use crate::pdu::init::VersionPdu;

    #[derive(Default, Debug)]
    struct HandlerState {
        names: Vec<(String, bool)>,
    }

    struct MockHandler {
        state: Arc<Mutex<HandlerState>>,
    }

    impl MockHandler {
        fn new() -> (Self, Arc<Mutex<HandlerState>>) {
            let state = Arc::new(Mutex::new(HandlerState::default()));
            (Self { state: state.clone() }, state)
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
        assert!(resp.is_empty(), "S1 has no S2 emits yet");

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
        server
            .process(&encode_with_header(PacketId::ClientName, &name))
            .unwrap();

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
}
