//! MS-RDPEPNP §3.2 — FileRedirectorChannel client state machine.
//!
//! One `FileRedirectorChannel` DVC instance carries the entire lifetime
//! of a single server-issued CreateFile call. The server opens a fresh
//! DVC each time it needs to open a redirected device handle, so a
//! JustRDP DVC host may see many such channels concurrently, each with
//! its own channel_id.
//!
//! This module provides:
//!
//! * [`FileRedirectorChannelClient`] — a [`DvcProcessor`] implementation
//!   that can multiplex many concurrent channel instances keyed by
//!   `channel_id`. Incoming messages are routed to a [`ChannelInstance`]
//!   which owns the per-channel FSM and an outstanding-request table.
//! * [`IoCallback`] — trait invoked for each inbound I/O request so the
//!   host application can service reads/writes/ioctls/cancels on the
//!   client side. All methods default to a `not-implemented` HRESULT.
//!
//! ```text
//! WaitCapabilities ──[ServerCapabilitiesRequest]──▶ WaitCreateFile
//!                       [emit ClientCapabilitiesReply]
//! WaitCreateFile ──[CreateFileRequest]──▶ Active
//!                       [emit CreateFileReply]
//! Active ──[Read/Write/IoControl/IoCancel]──▶ Active
//!                       [emit matching *Reply]
//! Active ──[close]──▶ Closed
//! ```

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::constants::{
    function_id, io_version, FILE_REDIRECTOR_CHANNEL_NAME, MAX_CHANNELS, MAX_OUTSTANDING_REQUESTS,
    SERVER_IO_HEADER_SIZE,
};
use crate::pdu::io::{
    ClientCapabilitiesReply, ClientDeviceCustomEvent, CreateFileReply, CreateFileRequest,
    IoControlReply, IoControlRequest, ReadReply, ReadRequest, ServerCapabilitiesRequest,
    SpecificIoCancelRequest, WriteReply, WriteRequest,
};
use crate::pdu::io_header::ServerIoHeader;

// ── FSM states ──

/// Position in the per-channel FileRedirectorChannel state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRedirectorState {
    /// Channel opened; awaiting [`ServerCapabilitiesRequest`].
    WaitCapabilities,
    /// Capabilities exchanged; awaiting [`CreateFileRequest`].
    WaitCreateFile,
    /// CreateFile replied; I/O requests allowed.
    Active,
    /// Channel closed or torn down by a protocol error.
    Closed,
}

// ── Errors ──

#[derive(Debug)]
pub enum FileRedirectorError {
    Decode(justrdp_core::DecodeError),
    Encode(justrdp_core::EncodeError),
    /// Some state/order/field rule was broken.
    Protocol(&'static str),
}

impl From<FileRedirectorError> for DvcError {
    fn from(e: FileRedirectorError) -> Self {
        match e {
            FileRedirectorError::Decode(d) => DvcError::Decode(d),
            FileRedirectorError::Encode(en) => DvcError::Encode(en),
            FileRedirectorError::Protocol(m) => {
                DvcError::Protocol(format!("RDPEPNP/FileRedirector: {m}"))
            }
        }
    }
}

// ── Outstanding requests ──

/// Kind of a request currently waiting for a client reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoRequestKind {
    Capabilities,
    CreateFile,
    Read,
    Write,
    IoControl {
        /// Advertised `cbOut` — the reply's Data length MUST NOT exceed
        /// this value (§2.2.2.3.8).
        cb_out: u32,
    },
}

// ── IoCallback trait ──

/// Application-facing contract for servicing inbound I/O requests.
///
/// Each method is called synchronously while the DvcProcessor is
/// handling an incoming server request. The host returns the Result
/// (and data, where applicable) the reply should carry on the wire.
///
/// The default implementation responds with HRESULT `E_NOTIMPL`
/// (`0x80004001`) so a consumer can opt into each operation
/// individually.
pub trait IoCallback {
    /// Handle a CreateFile request. Return the HRESULT to echo back in
    /// [`CreateFileReply`]. Returning a non-zero value does **not**
    /// automatically close the channel — the server decides.
    fn on_create_file(&mut self, _req: &CreateFileRequest) -> i32 {
        E_NOTIMPL
    }

    /// Handle a Read request. Return (result, data). `data.len()` must
    /// be ≤ `req.cb_bytes_to_read`; the processor enforces this.
    fn on_read(&mut self, _req: &ReadRequest) -> (i32, Vec<u8>) {
        (E_NOTIMPL, Vec::new())
    }

    /// Handle a Write request. Return (result, cb_bytes_written).
    fn on_write(&mut self, _req: &WriteRequest) -> (i32, u32) {
        (E_NOTIMPL, 0)
    }

    /// Handle an IoControl request. Return (result, data). `data.len()`
    /// must be ≤ `req.cb_out`.
    fn on_io_control(&mut self, _req: &IoControlRequest) -> (i32, Vec<u8>) {
        (E_NOTIMPL, Vec::new())
    }

    /// Notify the host that `id_to_cancel` should be cancelled. Purely
    /// advisory — there is no client reply for [`SpecificIoCancelRequest`].
    fn on_cancel(&mut self, _id_to_cancel: u32) {}
}

/// Standard Windows "not implemented" HRESULT.
pub const E_NOTIMPL: i32 = 0x8000_4001_u32 as i32;

/// Default no-op implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullIoCallback;

impl IoCallback for NullIoCallback {}

// ── ChannelInstance (per DVC channel_id) ──

/// Per-channel FSM and outstanding-request table.
#[derive(Debug)]
pub struct ChannelInstance {
    state: FileRedirectorState,
    /// Negotiated min(server, client) version once capabilities
    /// exchanged; `None` while still in [`WaitCapabilities`].
    negotiated_version: Option<u16>,
    /// `client_preferred_version` captured from the host at construct
    /// time so each new channel uses the same advertised value.
    client_preferred_version: u16,
    /// Outstanding server→client requests keyed by RequestId. Bounded
    /// by [`MAX_OUTSTANDING_REQUESTS`].
    outstanding: BTreeMap<u32, IoRequestKind>,
}

impl ChannelInstance {
    fn new(client_preferred_version: u16) -> Self {
        Self {
            state: FileRedirectorState::WaitCapabilities,
            negotiated_version: None,
            client_preferred_version,
            outstanding: BTreeMap::new(),
        }
    }

    pub fn state(&self) -> FileRedirectorState {
        self.state
    }

    pub fn negotiated_version(&self) -> Option<u16> {
        self.negotiated_version
    }

    pub fn outstanding_len(&self) -> usize {
        self.outstanding.len()
    }

    fn register(&mut self, id: u32, kind: IoRequestKind) -> Result<(), FileRedirectorError> {
        if self.outstanding.len() >= MAX_OUTSTANDING_REQUESTS {
            return Err(FileRedirectorError::Protocol(
                "outstanding request table full",
            ));
        }
        // Duplicate RequestId is a hard protocol violation (spec
        // Appendix §<11>: the client SHOULD tear down the DVC).
        if self.outstanding.contains_key(&id) {
            return Err(FileRedirectorError::Protocol("duplicate RequestId"));
        }
        self.outstanding.insert(id, kind);
        Ok(())
    }

    fn retire(&mut self, id: u32) {
        self.outstanding.remove(&id);
    }
}

// ── FileRedirectorChannelClient (DvcProcessor) ──

/// Multi-instance FileRedirectorChannel client.
///
/// Tracks one [`ChannelInstance`] per DVC `channel_id` — DRDYNVC is
/// allowed to open several concurrent channels sharing the
/// `"FileRedirectorChannel"` name, so the processor cannot assume a
/// single active channel the way [`crate::PnpInfoClient`] does for
/// the PNPDR control channel.
#[derive(Debug)]
pub struct FileRedirectorChannelClient<C: IoCallback = NullIoCallback> {
    /// Client-side preferred protocol version, used in every
    /// `ClientCapabilitiesReply` this processor emits.
    client_preferred_version: u16,
    instances: BTreeMap<u32, ChannelInstance>,
    callback: C,
}

impl FileRedirectorChannelClient<NullIoCallback> {
    /// Construct with the custom-event-capable version (0x0006) and a
    /// no-op callback.
    pub fn new() -> Self {
        Self::with_callback(NullIoCallback)
    }
}

impl Default for FileRedirectorChannelClient<NullIoCallback> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: IoCallback> FileRedirectorChannelClient<C> {
    pub fn with_callback(callback: C) -> Self {
        Self {
            client_preferred_version: io_version::CUSTOM_EVENT,
            instances: BTreeMap::new(),
            callback,
        }
    }

    /// Override the client's advertised protocol version. Must be one
    /// of [`io_version::NO_CUSTOM_EVENT`] or [`io_version::CUSTOM_EVENT`].
    pub fn with_version(mut self, version: u16) -> Self {
        self.client_preferred_version = version;
        self
    }

    pub fn instance(&self, channel_id: u32) -> Option<&ChannelInstance> {
        self.instances.get(&channel_id)
    }

    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    pub fn callback(&self) -> &C {
        &self.callback
    }

    pub fn callback_mut(&mut self) -> &mut C {
        &mut self.callback
    }

    /// Emit a self-initiated custom event on `channel_id`. Fails if the
    /// channel is not `Active` or the negotiated version does not
    /// support custom events.
    pub fn send_custom_event(
        &mut self,
        channel_id: u32,
        custom_event_guid: [u8; 16],
        data: Vec<u8>,
    ) -> Result<DvcMessage, FileRedirectorError> {
        let instance = self
            .instances
            .get(&channel_id)
            .ok_or(FileRedirectorError::Protocol("unknown channel_id"))?;
        if instance.state != FileRedirectorState::Active {
            return Err(FileRedirectorError::Protocol(
                "custom event before Active",
            ));
        }
        // Versions are additive: every version ≥ 0x0006 carries the
        // custom-event capability, so gate on "below 0x0006" rather
        // than strict equality — otherwise a future 0x0008 negotiation
        // would incorrectly block the feature.
        match instance.negotiated_version {
            Some(v) if v >= io_version::CUSTOM_EVENT => {}
            _ => {
                return Err(FileRedirectorError::Protocol(
                    "custom event requires negotiated version ≥ 0x0006",
                ));
            }
        }
        let evt = ClientDeviceCustomEvent {
            request_id: 0,
            custom_event_guid,
            data,
        };
        Ok(DvcMessage::new(encode_to_vec(&evt)?))
    }

    // ── Inbound dispatch ──

    fn handle_payload(
        &mut self,
        channel_id: u32,
        payload: &[u8],
    ) -> Result<Vec<DvcMessage>, FileRedirectorError> {
        if payload.len() < SERVER_IO_HEADER_SIZE {
            return Err(FileRedirectorError::Protocol(
                "payload shorter than SERVER_IO_HEADER",
            ));
        }
        // Peek at the header to decide dispatch; each branch then
        // re-decodes the full message from the original payload.
        let function_id = {
            let mut peek = ReadCursor::new(payload);
            let hdr = ServerIoHeader::decode(&mut peek).map_err(FileRedirectorError::Decode)?;
            hdr.function_id
        };

        match function_id {
            function_id::CAPABILITIES_REQUEST => {
                self.handle_capabilities(channel_id, payload)
            }
            function_id::CREATE_FILE_REQUEST => self.handle_create_file(channel_id, payload),
            function_id::READ_REQUEST => self.handle_read(channel_id, payload),
            function_id::WRITE_REQUEST => self.handle_write(channel_id, payload),
            function_id::IOCONTROL_REQUEST => self.handle_iocontrol(channel_id, payload),
            function_id::SPECIFIC_IOCANCEL_REQUEST => {
                self.handle_iocancel(channel_id, payload)
            }
            // §2.2.2.1.1 does not define any other FunctionId and spec
            // guidance is to terminate the channel on unknown values.
            _ => Err(FileRedirectorError::Protocol("unknown FunctionId")),
        }
    }

    fn handle_capabilities(
        &mut self,
        channel_id: u32,
        payload: &[u8],
    ) -> Result<Vec<DvcMessage>, FileRedirectorError> {
        let instance = self
            .instances
            .get_mut(&channel_id)
            .ok_or(FileRedirectorError::Protocol("unknown channel_id"))?;
        if instance.state != FileRedirectorState::WaitCapabilities {
            return Err(FileRedirectorError::Protocol(
                "Capabilities in unexpected state",
            ));
        }
        let req = decode_full::<ServerCapabilitiesRequest>(payload)?;
        // Negotiated version is the minimum of the two advertised
        // versions; spec §3.2.5.2.1 leaves this implicit but the
        // CUSTOM_EVENT gating in §2.2.2.3.10 only makes sense under the
        // min-rule.
        let negotiated = core::cmp::min(req.version, instance.client_preferred_version);
        instance.negotiated_version = Some(negotiated);
        instance.state = FileRedirectorState::WaitCreateFile;

        let reply = ClientCapabilitiesReply {
            request_id: req.request_id,
            version: instance.client_preferred_version,
        };
        Ok(alloc::vec![DvcMessage::new(encode_to_vec(&reply)?)])
    }

    fn handle_create_file(
        &mut self,
        channel_id: u32,
        payload: &[u8],
    ) -> Result<Vec<DvcMessage>, FileRedirectorError> {
        let req = decode_full::<CreateFileRequest>(payload)?;
        // Advance state and retire the outstanding slot *before*
        // invoking the callback: the callback cannot observe a
        // half-registered CreateFile, and a panic or early return
        // inside it cannot leave a stale RequestId in the table.
        {
            let instance = self
                .instances
                .get_mut(&channel_id)
                .ok_or(FileRedirectorError::Protocol("unknown channel_id"))?;
            if instance.state != FileRedirectorState::WaitCreateFile {
                return Err(FileRedirectorError::Protocol(
                    "CreateFile in unexpected state",
                ));
            }
            // register() is used here purely as a duplicate-RequestId
            // check — a matching CreateFile-reply is emitted
            // synchronously before this function returns, so there is
            // never any concurrent outstanding CreateFile slot. The
            // retire() call releases the transient slot immediately so
            // the Active-state outstanding table starts empty.
            instance.register(req.request_id, IoRequestKind::CreateFile)?;
            instance.retire(req.request_id);
            instance.state = FileRedirectorState::Active;
        }
        let result = self.callback.on_create_file(&req);

        let reply = CreateFileReply {
            request_id: req.request_id,
            result,
        };
        Ok(alloc::vec![DvcMessage::new(encode_to_vec(&reply)?)])
    }

    fn handle_read(
        &mut self,
        channel_id: u32,
        payload: &[u8],
    ) -> Result<Vec<DvcMessage>, FileRedirectorError> {
        let req = decode_full::<ReadRequest>(payload)?;
        self.require_active(channel_id, req.request_id, IoRequestKind::Read)?;
        let (result, mut data) = self.callback.on_read(&req);
        // Enforce the "cbBytesRead ≤ cbBytesToRead" invariant the
        // application might have violated.
        if data.len() > req.cb_bytes_to_read as usize {
            data.truncate(req.cb_bytes_to_read as usize);
        }
        let instance = self
            .instances
            .get_mut(&channel_id)
            .ok_or(FileRedirectorError::Protocol(
                "channel disappeared during callback",
            ))?;
        instance.retire(req.request_id);
        let reply = ReadReply {
            request_id: req.request_id,
            result,
            data,
        };
        Ok(alloc::vec![DvcMessage::new(encode_to_vec(&reply)?)])
    }

    fn handle_write(
        &mut self,
        channel_id: u32,
        payload: &[u8],
    ) -> Result<Vec<DvcMessage>, FileRedirectorError> {
        let req = decode_full::<WriteRequest>(payload)?;
        self.require_active(channel_id, req.request_id, IoRequestKind::Write)?;
        let (result, cb_bytes_written) = self.callback.on_write(&req);
        let instance = self
            .instances
            .get_mut(&channel_id)
            .ok_or(FileRedirectorError::Protocol(
                "channel disappeared during callback",
            ))?;
        instance.retire(req.request_id);
        let reply = WriteReply {
            request_id: req.request_id,
            result,
            cb_bytes_written,
        };
        Ok(alloc::vec![DvcMessage::new(encode_to_vec(&reply)?)])
    }

    fn handle_iocontrol(
        &mut self,
        channel_id: u32,
        payload: &[u8],
    ) -> Result<Vec<DvcMessage>, FileRedirectorError> {
        let req = decode_full::<IoControlRequest>(payload)?;
        self.require_active(
            channel_id,
            req.request_id,
            IoRequestKind::IoControl { cb_out: req.cb_out },
        )?;
        let (result, mut data) = self.callback.on_io_control(&req);
        if data.len() > req.cb_out as usize {
            data.truncate(req.cb_out as usize);
        }
        let instance = self
            .instances
            .get_mut(&channel_id)
            .ok_or(FileRedirectorError::Protocol(
                "channel disappeared during callback",
            ))?;
        instance.retire(req.request_id);
        let reply = IoControlReply {
            request_id: req.request_id,
            result,
            data,
        };
        Ok(alloc::vec![DvcMessage::new(encode_to_vec(&reply)?)])
    }

    fn handle_iocancel(
        &mut self,
        channel_id: u32,
        payload: &[u8],
    ) -> Result<Vec<DvcMessage>, FileRedirectorError> {
        let req = decode_full::<SpecificIoCancelRequest>(payload)?;
        let instance = self
            .instances
            .get_mut(&channel_id)
            .ok_or(FileRedirectorError::Protocol("unknown channel_id"))?;
        if instance.state != FileRedirectorState::Active {
            return Err(FileRedirectorError::Protocol("Cancel before Active"));
        }
        // Spec does not mandate a reply for cancel; retire the target
        // RequestId if it's tracked, otherwise silently ignore.
        if instance.outstanding.remove(&req.id_to_cancel).is_some() {
            self.callback.on_cancel(req.id_to_cancel);
        }
        Ok(Vec::new())
    }

    fn require_active(
        &mut self,
        channel_id: u32,
        request_id: u32,
        kind: IoRequestKind,
    ) -> Result<(), FileRedirectorError> {
        let instance = self
            .instances
            .get_mut(&channel_id)
            .ok_or(FileRedirectorError::Protocol("unknown channel_id"))?;
        if instance.state != FileRedirectorState::Active {
            return Err(FileRedirectorError::Protocol("I/O before Active"));
        }
        instance.register(request_id, kind)?;
        Ok(())
    }
}

fn decode_full<T>(payload: &[u8]) -> Result<T, FileRedirectorError>
where
    for<'de> T: Decode<'de>,
{
    let mut cur = ReadCursor::new(payload);
    let msg = T::decode(&mut cur).map_err(FileRedirectorError::Decode)?;
    if cur.remaining() != 0 {
        return Err(FileRedirectorError::Protocol("trailing bytes"));
    }
    Ok(msg)
}

fn encode_to_vec<E: Encode>(pdu: &E) -> Result<Vec<u8>, FileRedirectorError> {
    let mut buf = alloc::vec![0u8; pdu.size()];
    let mut cur = WriteCursor::new(&mut buf);
    pdu.encode(&mut cur).map_err(FileRedirectorError::Encode)?;
    Ok(buf)
}

// ── AsAny / DvcProcessor ──

impl<C> AsAny for FileRedirectorChannelClient<C>
where
    C: IoCallback + Send + core::fmt::Debug + 'static,
{
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl<C> DvcProcessor for FileRedirectorChannelClient<C>
where
    C: IoCallback + Send + core::fmt::Debug + 'static,
{
    fn channel_name(&self) -> &str {
        FILE_REDIRECTOR_CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        // DRDYNVC may recycle a channel_id across distinct CreateFile
        // calls. A fresh `start()` always wipes any stale instance
        // state for that id before the peer begins a new handshake.
        // The MAX_CHANNELS cap only applies to *new* channel_ids; a
        // restart of an already-tracked id is allowed so the peer can
        // recover from a broken channel without tripping the limit.
        if !self.instances.contains_key(&channel_id) && self.instances.len() >= MAX_CHANNELS {
            return Err(DvcError::Protocol(format!(
                "RDPEPNP/FileRedirector: channel table full (cap={MAX_CHANNELS})"
            )));
        }
        self.instances
            .insert(channel_id, ChannelInstance::new(self.client_preferred_version));
        Ok(Vec::new())
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if !self.instances.contains_key(&channel_id) {
            return Err(DvcError::Protocol(String::from(
                "RDPEPNP/FileRedirector: process() before start()",
            )));
        }
        // Any error on this channel is fatal. Protocol errors (spec
        // §<11> / §2.2.2.1.1: duplicate RequestId, unknown FunctionId,
        // out-of-order message) obviously require tear-down. Decode
        // and Encode failures are treated the same way: a partially
        // decoded request or a half-formed reply would desync the
        // client from the server's view of the outstanding table, and
        // there is no defined recovery path once that happens. Stamp
        // the FSM as `Closed` before propagating so a re-entrant
        // `process()` call from a lax DVC host cannot find the
        // instance in a live state — the host is still expected to
        // call `close()` to drop the entry entirely.
        match self.handle_payload(channel_id, payload) {
            Ok(msgs) => Ok(msgs),
            Err(e) => {
                if let Some(inst) = self.instances.get_mut(&channel_id) {
                    inst.state = FileRedirectorState::Closed;
                    inst.outstanding.clear();
                }
                Err(e.into())
            }
        }
    }

    fn close(&mut self, channel_id: u32) {
        // Dropping the instance discards its outstanding-request table
        // — the server has already torn the channel down so none of
        // the tracked RequestIds will ever be answered.
        self.instances.remove(&channel_id);
    }
}
