//! MS-RDPEPNP §3.1 — PNPDR DVC processor and device registry.
//!
//! Implements the PNPDR control channel state machine:
//!
//! ```text
//! WaitServerVersion ──[ServerVersion]──▶ WaitAuthenticated ──[AuthenticatedClient]──▶ Active
//! ```
//!
//! Once `Active`, the user application calls [`PnpInfoClient::add_device`]
//! and [`PnpInfoClient::remove_device`] to enqueue device announcements;
//! the resulting wire messages are returned as [`DvcMessage`]s for the
//! DRDYNVC host to dispatch. Callbacks ([`PnpInfoCallback`]) fire for
//! every add/remove, preserving the balanced-callback invariant used
//! throughout the rest of JustRDP.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::constants::{
    packet_id, MAX_DEVICES, MAX_DEVICE_DESCRIPTION_BYTES, MAX_HARDWARE_ID_BYTES,
    MAX_INTERFACE_BYTES, PNPDR_CHANNEL_NAME, PNP_INFO_HEADER_SIZE,
};
use crate::pdu::{
    AuthenticatedClientMsg, ClientDeviceAdditionMsg, ClientDeviceRemovalMsg, ClientVersionMsg,
    PnpDeviceDescription, PnpInfoHeader, ServerVersionMsg,
};

// ── DeviceEntry ──

/// A single tracked client device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEntry {
    /// Friendly description — useful for logging. Stored as raw UTF-16LE
    /// bytes so round-trip fidelity is preserved.
    pub device_description: Vec<u8>,
    /// CustomFlag (see [`crate::constants::custom_flag`]).
    pub custom_flag: u32,
    /// Optional ContainerId (RDP 7.0+).
    pub container_id: Option<[u8; 16]>,
    /// Optional DeviceCaps (RDP 7.0+).
    pub device_caps: Option<u32>,
}

impl DeviceEntry {
    fn from_description(d: &PnpDeviceDescription) -> Self {
        Self {
            device_description: d.device_description.clone(),
            custom_flag: d.custom_flag,
            container_id: d.container_id,
            device_caps: d.device_caps,
        }
    }
}

// ── Callback trait ──

/// Observer notified when the local device table changes.
///
/// All methods default to no-ops so consumers only implement the events
/// they care about.
///
/// **Balanced invariant**: for every `on_device_added`, exactly one
/// `on_device_removed` will fire for the same `client_device_id`, with
/// one exception — calling [`PnpInfoClient::add_device`] twice with the
/// same ID replaces the entry in place and fires `on_device_added` a
/// second time without an intervening `on_device_removed`. A duplicate
/// announcement is an *update* of a still-present device, not a
/// remove-and-re-create cycle; injecting a synthetic `on_device_removed`
/// would create a window where observers believe the device vanished,
/// which is worse than firing `on_device_added` twice. This mirrors the
/// pattern used by `justrdp-rdpemc`'s callback contract.
pub trait PnpInfoCallback {
    /// Called when a device enters the local registry via
    /// [`PnpInfoClient::add_device`].
    fn on_device_added(&mut self, _client_device_id: u32, _entry: &DeviceEntry) {}

    /// Called when a device is removed via [`PnpInfoClient::remove_device`]
    /// or when the channel closes and the table is flushed.
    fn on_device_removed(&mut self, _client_device_id: u32) {}

    /// Called once the `PNPDR` handshake reaches [`PnpInfoState::Active`].
    fn on_authenticated(&mut self) {}
}

/// Default [`PnpInfoCallback`] implementation that ignores every event.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullCallback;

impl PnpInfoCallback for NullCallback {}

// ── Errors ──

/// Errors raised by [`PnpInfoClient`].
#[derive(Debug)]
pub enum PnpInfoError {
    /// Wire decode error bubbling up from the PDU layer.
    Decode(justrdp_core::DecodeError),
    /// Wire encode error bubbling up from the PDU layer.
    Encode(justrdp_core::EncodeError),
    /// Device registry is full. `cap` is [`MAX_DEVICES`].
    TableFull { cap: usize },
    /// Some other protocol-level violation — e.g. unexpected message for
    /// the current state, or a field overflow.
    Protocol(&'static str),
}

impl From<PnpInfoError> for DvcError {
    // All variants surface as Protocol(String) once they reach the DVC
    // layer: a `TableFull` or out-of-state `add_device` call is a contract
    // violation by the caller just like a malformed wire message from a
    // peer, so the channel should be torn down regardless.
    fn from(e: PnpInfoError) -> Self {
        match e {
            PnpInfoError::Decode(d) => DvcError::Decode(d),
            PnpInfoError::Encode(en) => DvcError::Encode(en),
            PnpInfoError::TableFull { cap } => {
                DvcError::Protocol(format!("RDPEPNP: device table full (cap={cap})"))
            }
            PnpInfoError::Protocol(msg) => DvcError::Protocol(format!("RDPEPNP: {msg}")),
        }
    }
}

// ── FSM state ──

/// PNPDR client state machine position (MS-RDPEPNP §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnpInfoState {
    /// Channel opened; awaiting Server Version Message from the peer.
    WaitServerVersion,
    /// Client Version Message sent; awaiting Authenticated Client Message.
    WaitAuthenticated,
    /// Active — may send device add/remove messages.
    Active,
    /// Channel closed by the DRDYNVC host.
    Closed,
}

// ── PnpInfoClient ──

/// Client-side processor for the `"PNPDR"` dynamic virtual channel.
///
/// Generic over the callback type so that applications can plug their
/// own observer without resorting to trait-object dynamic dispatch
/// (which would need `Send + 'static` bounds and `Box<dyn>` indirection).
/// A unit callback is selected with [`NullCallback`].
#[derive(Debug)]
pub struct PnpInfoClient<C: PnpInfoCallback = NullCallback> {
    state: PnpInfoState,
    channel_id: u32,
    channel_open: bool,
    server_version: Option<ServerVersionMsg>,
    devices: BTreeMap<u32, DeviceEntry>,
    callback: C,
}

impl PnpInfoClient<NullCallback> {
    /// Construct with a no-op callback.
    pub fn new() -> Self {
        Self::with_callback(NullCallback)
    }
}

impl Default for PnpInfoClient<NullCallback> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: PnpInfoCallback> PnpInfoClient<C> {
    /// Construct with an application-supplied callback.
    pub fn with_callback(callback: C) -> Self {
        Self {
            state: PnpInfoState::WaitServerVersion,
            channel_id: 0,
            channel_open: false,
            server_version: None,
            devices: BTreeMap::new(),
            callback,
        }
    }

    /// Current FSM state.
    pub fn state(&self) -> PnpInfoState {
        self.state
    }

    /// Whether the underlying DVC is open.
    pub fn is_open(&self) -> bool {
        self.channel_open
    }

    /// The Server Version Message recorded during handshake, if any.
    pub fn server_version(&self) -> Option<&ServerVersionMsg> {
        self.server_version.as_ref()
    }

    /// Number of currently tracked client devices.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Read-only access to a tracked device.
    pub fn device(&self, client_device_id: u32) -> Option<&DeviceEntry> {
        self.devices.get(&client_device_id)
    }

    /// Iterator over tracked devices.
    pub fn devices(&self) -> impl Iterator<Item = (u32, &DeviceEntry)> {
        self.devices.iter().map(|(id, e)| (*id, e))
    }

    /// Access the inner callback.
    pub fn callback(&self) -> &C {
        &self.callback
    }

    /// Mutable access to the inner callback.
    pub fn callback_mut(&mut self) -> &mut C {
        &mut self.callback
    }

    // ── Outbound API ──

    /// Announce a single device to the server. Only valid in
    /// [`PnpInfoState::Active`].
    ///
    /// Returns the wire bytes of a `Client Device Addition Message`
    /// carrying exactly this one device. Callbacks fire after the
    /// internal table update.
    pub fn add_device(
        &mut self,
        description: PnpDeviceDescription,
    ) -> Result<DvcMessage, PnpInfoError> {
        if self.state != PnpInfoState::Active {
            return Err(PnpInfoError::Protocol("add_device before Active"));
        }
        self.validate_description(&description)?;

        let id = description.client_device_id;
        let entry = DeviceEntry::from_description(&description);
        let inserting_new = !self.devices.contains_key(&id);
        if inserting_new && self.devices.len() >= MAX_DEVICES {
            return Err(PnpInfoError::TableFull { cap: MAX_DEVICES });
        }

        // Encode BEFORE updating internal state so a size/overflow error
        // doesn't leave the table inconsistent with the wire.
        let msg = ClientDeviceAdditionMsg::new(alloc::vec![description]);
        let bytes = encode_to_vec(&msg)?;

        self.devices.insert(id, entry.clone());
        self.callback.on_device_added(id, &entry);
        Ok(DvcMessage::new(bytes))
    }

    /// Request removal of a previously announced device. Only valid in
    /// [`PnpInfoState::Active`] and only for an ID present in the table.
    pub fn remove_device(
        &mut self,
        client_device_id: u32,
    ) -> Result<DvcMessage, PnpInfoError> {
        if self.state != PnpInfoState::Active {
            return Err(PnpInfoError::Protocol("remove_device before Active"));
        }
        if self.devices.remove(&client_device_id).is_none() {
            return Err(PnpInfoError::Protocol("remove_device: unknown id"));
        }
        let msg = ClientDeviceRemovalMsg { client_device_id };
        let bytes = encode_to_vec(&msg)?;
        self.callback.on_device_removed(client_device_id);
        Ok(DvcMessage::new(bytes))
    }

    fn validate_description(&self, d: &PnpDeviceDescription) -> Result<(), PnpInfoError> {
        if d.interface_guid_array.len() > MAX_INTERFACE_BYTES {
            return Err(PnpInfoError::Protocol("InterfaceGUIDArray too long"));
        }
        if d.interface_guid_array.len() % 16 != 0 {
            return Err(PnpInfoError::Protocol(
                "InterfaceGUIDArray not 16-byte aligned",
            ));
        }
        if d.hardware_id.len() > MAX_HARDWARE_ID_BYTES {
            return Err(PnpInfoError::Protocol("HardwareId too long"));
        }
        if d.compatibility_id.len() > MAX_HARDWARE_ID_BYTES {
            return Err(PnpInfoError::Protocol("CompatibilityID too long"));
        }
        if d.device_description.len() > MAX_DEVICE_DESCRIPTION_BYTES {
            return Err(PnpInfoError::Protocol("DeviceDescription too long"));
        }
        Ok(())
    }

    // ── Inbound handling ──

    fn handle_server_version(
        &mut self,
        payload: &[u8],
    ) -> Result<Vec<DvcMessage>, PnpInfoError> {
        if self.state != PnpInfoState::WaitServerVersion {
            return Err(PnpInfoError::Protocol(
                "ServerVersion in unexpected state",
            ));
        }
        let mut cur = ReadCursor::new(payload);
        let msg = ServerVersionMsg::decode(&mut cur).map_err(PnpInfoError::Decode)?;
        if cur.remaining() != 0 {
            return Err(PnpInfoError::Protocol("trailing bytes after ServerVersion"));
        }
        self.server_version = Some(msg);
        self.state = PnpInfoState::WaitAuthenticated;

        let reply = ClientVersionMsg::new_client_windows_default();
        let bytes = encode_to_vec(&reply)?;
        Ok(alloc::vec![DvcMessage::new(bytes)])
    }

    fn handle_authenticated(
        &mut self,
        payload: &[u8],
    ) -> Result<Vec<DvcMessage>, PnpInfoError> {
        if self.state != PnpInfoState::WaitAuthenticated {
            return Err(PnpInfoError::Protocol(
                "AuthenticatedClient in unexpected state",
            ));
        }
        let mut cur = ReadCursor::new(payload);
        AuthenticatedClientMsg::decode(&mut cur).map_err(PnpInfoError::Decode)?;
        if cur.remaining() != 0 {
            return Err(PnpInfoError::Protocol(
                "trailing bytes after AuthenticatedClient",
            ));
        }
        self.state = PnpInfoState::Active;
        self.callback.on_authenticated();
        Ok(Vec::new())
    }

    /// Flush every tracked device, firing `on_device_removed` for each.
    fn flush_devices(&mut self) {
        // Collect key list first so we can iterate while mutating the map.
        // `BTreeMap::keys()` already produces sorted unique u32s so a Vec
        // is enough.
        let ids: Vec<u32> = self.devices.keys().copied().collect();
        self.devices.clear();
        for id in ids {
            self.callback.on_device_removed(id);
        }
    }
}

fn encode_to_vec<E: Encode>(pdu: &E) -> Result<Vec<u8>, PnpInfoError> {
    let mut buf = alloc::vec![0u8; pdu.size()];
    let mut cur = WriteCursor::new(&mut buf);
    pdu.encode(&mut cur).map_err(PnpInfoError::Encode)?;
    Ok(buf)
}

// ── AsAny / DvcProcessor ──

impl<C> AsAny for PnpInfoClient<C>
where
    C: PnpInfoCallback + Send + core::fmt::Debug + 'static,
{
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl<C> DvcProcessor for PnpInfoClient<C>
where
    C: PnpInfoCallback + Send + core::fmt::Debug + 'static,
{
    fn channel_name(&self) -> &str {
        PNPDR_CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        // DRDYNVC may re-open this channel after a server-side close; drop
        // any stale device state from the previous lifetime. Fire callbacks
        // so observers stay balanced.
        self.flush_devices();
        self.state = PnpInfoState::WaitServerVersion;
        self.channel_id = channel_id;
        self.channel_open = true;
        self.server_version = None;
        Ok(Vec::new())
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if !self.channel_open {
            return Err(DvcError::Protocol(String::from(
                "RDPEPNP process() before start()",
            )));
        }
        if channel_id != self.channel_id {
            return Err(DvcError::Protocol(String::from(
                "RDPEPNP: channel_id mismatch in process()",
            )));
        }
        if payload.len() < PNP_INFO_HEADER_SIZE {
            return Err(DvcError::Protocol(String::from(
                "RDPEPNP: payload shorter than PNP_INFO_HEADER",
            )));
        }

        // Peek at the PacketId without consuming the cursor.
        let mut peek = ReadCursor::new(payload);
        let hdr = PnpInfoHeader::decode(&mut peek).map_err(DvcError::Decode)?;
        // Spec requires the header `Size` to equal the payload length
        // exactly. DRDYNVC already reassembled the message for us, so a
        // mismatch is a protocol error.
        if hdr.size as usize != payload.len() {
            return Err(DvcError::Protocol(String::from(
                "RDPEPNP: PNP_INFO_HEADER.Size != DVC payload length",
            )));
        }

        match hdr.packet_id {
            packet_id::IRPDR_ID_VERSION => Ok(self.handle_server_version(payload)?),
            packet_id::IRPDR_ID_SERVER_LOGON => Ok(self.handle_authenticated(payload)?),
            // The server never sends REDIRECT_DEVICES / UNREDIRECT_DEVICE
            // to the client; treat them as protocol violations.
            packet_id::IRPDR_ID_REDIRECT_DEVICES | packet_id::IRPDR_ID_UNREDIRECT_DEVICE => {
                Err(DvcError::Protocol(String::from(
                    "RDPEPNP: server sent client-only PacketId",
                )))
            }
            // Forward-compat: unknown PacketId — silently skip. The spec
            // does not define a termination rule for unknown control
            // messages on PNPDR, so a future protocol revision may add
            // new S→C packets. The DRDYNVC layer framed the payload, so
            // dropping it here loses nothing.
            _ => Ok(Vec::new()),
        }
    }

    fn close(&mut self, channel_id: u32) {
        // `DvcProcessor::close` has no return type, so a mismatched
        // `channel_id` cannot surface an error — but silently wiping
        // state that belongs to a still-open channel would be worse
        // than a no-op. Ignore foreign ids regardless of open state so
        // the guard is symmetric with `process()`'s id check.
        if !self.channel_open {
            return;
        }
        if channel_id != self.channel_id {
            return;
        }
        self.flush_devices();
        self.state = PnpInfoState::Closed;
        self.channel_open = false;
        self.channel_id = 0;
        self.server_version = None;
    }
}

