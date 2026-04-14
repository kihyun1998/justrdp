//! [`RdpevClient`] -- the TSMF DVC processor.
//!
//! Drives a single TSMF channel through its lifecycle and routes
//! every incoming PDU to the [`crate::media::TsmfMediaSink`] host
//! trait. The channel multiplexes multiple presentations -- each
//! identified by a 16-byte `PresentationId` GUID -- and each
//! presentation may carry multiple streams.
//!
//! ## Channel state machine
//!
//! ```text
//!   Uninitialised
//!         │ start()
//!         ▼
//!     Initialised  ←──→  presentations: BTreeMap<Guid, PresentationContext>
//!         │ close()
//!         ▼
//!       Closed
//! ```
//!
//! Transition rules:
//!
//! - `start()` is called by the DVC framework once when the channel
//!   opens. It moves the FSM to `Initialised` and emits no PDUs.
//! - The channel must accept its first `SET_CHANNEL_PARAMS` before
//!   any presentation arrives; subsequent `SET_CHANNEL_PARAMS` after
//!   the bind is a protocol violation per spec §3.3.5.1.
//! - `close()` moves the FSM to `Closed` and clears every
//!   presentation. It is idempotent.
//!
//! ## Per-presentation state machine
//!
//! ```text
//!   Created  ── ADD_STREAM (×N)        ──►  Setup
//!     ▲                                       │ SET_TOPOLOGY_REQ → RSP
//!     │                                       ▼
//!  ON_NEW_PRESENTATION                      Ready  ←─→ ON_SAMPLE / control
//!                                             │ SHUTDOWN_PRESENTATION_REQ
//!                                             ▼
//!                                          Terminated
//! ```
//!
//! Step 3a only ships the channel skeleton plus the four entry-point
//! handlers (`EXCHANGE_CAPABILITIES_REQ`, `SET_CHANNEL_PARAMS`,
//! `ON_NEW_PRESENTATION`, `CHECK_FORMAT_SUPPORT_REQ`). The remaining
//! 21 handlers and the `OnSample` hot path land in Step 3b.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::constants::{unpack_interface_id, FunctionId, InterfaceValue, Mask, S_OK};
use crate::media::{result_to_hresult, CheckFormatResult, TsmfMediaSink};
use crate::pdu::capabilities::{ExchangeCapabilitiesReq, ExchangeCapabilitiesRsp};
use crate::pdu::control::{
    NotifyPreroll, OnEndOfStream, OnFlush, OnPlaybackPaused, OnPlaybackRateChanged,
    OnPlaybackRestarted, OnPlaybackStarted, OnPlaybackStopped,
};
use crate::pdu::format::{CheckFormatSupportReq, CheckFormatSupportRsp, TsAmMediaType};
use crate::pdu::geometry::{SetSourceVideoRect, SetVideoWindow, UpdateGeometryInfo};
use crate::pdu::guid::{Guid, GUID_SIZE};
use crate::pdu::misc::{ClientEventNotification, OnChannelVolume, OnStreamVolume, SetAllocator};
use crate::pdu::presentation::{
    OnNewPresentation, SetChannelParams, SetTopologyReq, SetTopologyRsp, ShutdownPresentationReq,
    ShutdownPresentationRsp,
};
use crate::pdu::sample::{OnSample, PlaybackAck};
use crate::pdu::stream::{AddStream, RemoveStream};
use crate::CHANNEL_NAME;

// ── DoS caps ────────────────────────────────────────────────────────

/// Maximum number of presentations the channel can hold simultaneously.
pub const MAX_PRESENTATIONS: usize = 16;

/// Maximum number of streams per presentation.
pub const MAX_STREAMS_PER_PRESENTATION: usize = 64;

// ── State enums ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelState {
    Uninitialised,
    Initialised,
    Closed,
}

/// Per-presentation lifecycle.
///
/// `Created` is the state right after `ON_NEW_PRESENTATION` and
/// before the first `ADD_STREAM`. `Setup` is reached on the first
/// `ADD_STREAM` and stays there as more streams are added. `Ready`
/// is reached when the server's `SET_TOPOLOGY_REQ` has been answered
/// with `topology_ready = 1`; this is the only state in which
/// `ON_SAMPLE` is expected. `Terminated` is set briefly while a
/// `SHUTDOWN_PRESENTATION_REQ` is being processed before the
/// presentation is removed from the map entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PresentationState {
    Created,
    Setup,
    Ready,
    Terminated,
}

/// Per-stream lifecycle. Reaches `Streaming` on the first `ON_SAMPLE`
/// the stream sees; `Stopped` is currently a placeholder for future
/// fine-grained flow control (the wire protocol only has whole-
/// presentation playback states).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamState {
    Added,
    Streaming,
    #[allow(dead_code)]
    Stopped,
}

// ── Per-presentation context ────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct StreamContext {
    #[allow(dead_code)]
    pub media_type: TsAmMediaType,
    pub state: StreamState,
}

#[derive(Debug, Clone)]
pub(crate) struct PresentationContext {
    pub state: PresentationState,
    #[allow(dead_code)]
    pub platform_cookie: u32,
    pub streams: BTreeMap<u32, StreamContext>,
}

impl PresentationContext {
    fn new(platform_cookie: u32) -> Self {
        Self {
            state: PresentationState::Created,
            platform_cookie,
            streams: BTreeMap::new(),
        }
    }
}

// ── Channel-level bind state ────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChannelBind {
    presentation_id: Guid,
    stream_id: u32,
}

// ── RdpevClient processor ───────────────────────────────────────────

/// DVC processor for the static `TSMF` channel.
///
/// Holds the host's [`TsmfMediaSink`], a presentation map, and the
/// channel-level FSM. Constructed once per channel; the
/// [`DvcProcessor`] trait drives it from `justrdp-dvc`.
pub struct RdpevClient {
    sink: Box<dyn TsmfMediaSink>,
    state: ChannelState,
    channel_id: u32,
    /// Presentation map; key is the raw 16 GUID bytes (so the
    /// `Guid` newtype can stay `Copy` while we still use it as a
    /// `BTreeMap` key without reallocating on lookup).
    presentations: BTreeMap<[u8; GUID_SIZE], PresentationContext>,
    /// `(presentation_id, stream_id)` from the first
    /// `SET_CHANNEL_PARAMS`; `None` until the bind has happened.
    bind: Option<ChannelBind>,
    /// Monotonic counter used for outbound (`PLAYBACK_ACK`,
    /// `CLIENT_EVENT_NOTIFICATION`) `MessageId` values. Wraps freely.
    next_message_id: u32,
}

impl core::fmt::Debug for RdpevClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdpevClient")
            .field("state", &self.state)
            .field("channel_id", &self.channel_id)
            .field("presentations", &self.presentations.len())
            .field("bind", &self.bind)
            .field("next_message_id", &self.next_message_id)
            .finish()
    }
}

impl RdpevClient {
    /// Constructs a new TSMF processor wired to the given sink.
    pub fn new(sink: Box<dyn TsmfMediaSink>) -> Self {
        Self {
            sink,
            state: ChannelState::Uninitialised,
            channel_id: 0,
            presentations: BTreeMap::new(),
            bind: None,
            next_message_id: 0,
        }
    }

    /// True iff `start()` has been called and `close()` has not.
    pub fn is_open(&self) -> bool {
        matches!(self.state, ChannelState::Initialised)
    }

    /// Number of presentations currently tracked by the channel.
    pub fn presentation_count(&self) -> usize {
        self.presentations.len()
    }

    /// Returns the channel-level bind, if `SET_CHANNEL_PARAMS` has
    /// already been processed.
    pub fn bound_presentation(&self) -> Option<Guid> {
        self.bind.map(|b| b.presentation_id)
    }

    // ── Internal helpers ──

    fn ensure_open(&self, ctx: &'static str) -> DvcResult<()> {
        if self.state != ChannelState::Initialised {
            return Err(DvcError::Protocol(format!(
                "{ctx}: channel not in Initialised state ({:?})",
                self.state
            )));
        }
        Ok(())
    }

    /// Allocates the next outbound `MessageId` for client-originated
    /// PDUs (`PLAYBACK_ACK`, `CLIENT_EVENT_NOTIFICATION`). Wraps freely.
    /// Used by Step 3b handlers; suppressed here to keep the skeleton
    /// warning-clean.
    #[allow(dead_code)]
    fn next_msg_id(&mut self) -> u32 {
        let id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        id
    }

    /// Encodes a PDU into a `DvcMessage` in one shot.
    pub(crate) fn encode_pdu<E: Encode>(pdu: &E) -> DvcResult<DvcMessage> {
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur)?;
        debug_assert_eq!(cur.pos(), pdu.size(), "size() mismatch in {}", pdu.name());
        Ok(DvcMessage::new(buf))
    }

    // ── Top-level dispatch ──

    /// Peeks the SHARED_MSG_HEADER prefix to decide which decoder to
    /// run. We do NOT use `decode_header_auto` directly because each
    /// per-PDU decoder does its own header decode and we need the
    /// dispatch tuple to route the payload first.
    fn dispatch(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if payload.len() < 8 {
            return Err(DvcError::Protocol(String::from(
                "MS-RDPEV: payload smaller than response header",
            )));
        }
        let raw_iface = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let (iv_raw, mask) = unpack_interface_id(raw_iface);
        let interface_value = InterfaceValue::from_u32(iv_raw);

        match mask {
            Mask::Stub => {
                // The server never sends responses on this channel
                // (we are the client; only client→server PDUs use
                // STUB). Treat as a protocol error rather than
                // silently dropping it.
                Err(DvcError::Protocol(String::from(
                    "MS-RDPEV: unexpected STUB-masked PDU from server",
                )))
            }
            Mask::None => {
                // Interface manipulation (RIMCALL_*) -- not yet
                // supported. We log and ignore so a future spec
                // extension does not tear the channel down.
                Ok(Vec::new())
            }
            Mask::Other(_) => Err(DvcError::Protocol(String::from(
                "MS-RDPEV: unknown Mask bits in InterfaceId",
            ))),
            Mask::Proxy => {
                // Request from the server -- pull the FunctionId.
                if payload.len() < 12 {
                    return Err(DvcError::Protocol(String::from(
                        "MS-RDPEV: PROXY payload smaller than 12-byte header",
                    )));
                }
                let raw_fid =
                    u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
                let fid = FunctionId::from_raw(iv_raw, raw_fid);
                self.dispatch_request(interface_value, fid, payload)
            }
        }
    }

    fn dispatch_request(
        &mut self,
        interface_value: InterfaceValue,
        fid: FunctionId,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
        // Route ServerData interface PDUs we know about. Unknown
        // FunctionIds on either interface are ignored per spec §9
        // ("ignore unknown") so that a future spec extension does not
        // tear the channel down.
        match (interface_value, fid) {
            // ── Capability + bind ──
            (InterfaceValue::ServerData, FunctionId::ExchangeCapabilitiesReq) => {
                self.handle_exchange_capabilities_req(payload)
            }
            (InterfaceValue::ServerData, FunctionId::SetChannelParams) => {
                self.handle_set_channel_params(payload)
            }
            // ── Presentation lifecycle ──
            (InterfaceValue::ServerData, FunctionId::OnNewPresentation) => {
                self.handle_on_new_presentation(payload)
            }
            (InterfaceValue::ServerData, FunctionId::CheckFormatSupportReq) => {
                self.handle_check_format_support_req(payload)
            }
            (InterfaceValue::ServerData, FunctionId::AddStream) => {
                self.handle_add_stream(payload)
            }
            (InterfaceValue::ServerData, FunctionId::SetTopologyReq) => {
                self.handle_set_topology_req(payload)
            }
            (InterfaceValue::ServerData, FunctionId::RemoveStream) => {
                self.handle_remove_stream(payload)
            }
            (InterfaceValue::ServerData, FunctionId::ShutdownPresentationReq) => {
                self.handle_shutdown_presentation_req(payload)
            }
            // ── Hot path ──
            (InterfaceValue::ServerData, FunctionId::OnSample) => self.handle_on_sample(payload),
            // ── Playback control ──
            (InterfaceValue::ServerData, FunctionId::NotifyPreroll) => {
                self.handle_notify_preroll(payload)
            }
            (InterfaceValue::ServerData, FunctionId::OnFlush) => self.handle_on_flush(payload),
            (InterfaceValue::ServerData, FunctionId::OnEndOfStream) => {
                self.handle_on_end_of_stream(payload)
            }
            (InterfaceValue::ServerData, FunctionId::OnPlaybackStarted) => {
                self.handle_on_playback_started(payload)
            }
            (InterfaceValue::ServerData, FunctionId::OnPlaybackPaused) => {
                self.handle_on_playback_paused(payload)
            }
            (InterfaceValue::ServerData, FunctionId::OnPlaybackStopped) => {
                self.handle_on_playback_stopped(payload)
            }
            (InterfaceValue::ServerData, FunctionId::OnPlaybackRestarted) => {
                self.handle_on_playback_restarted(payload)
            }
            (InterfaceValue::ServerData, FunctionId::OnPlaybackRateChanged) => {
                self.handle_on_playback_rate_changed(payload)
            }
            // ── Volume / geometry / window / allocator ──
            (InterfaceValue::ServerData, FunctionId::OnStreamVolume) => {
                self.handle_on_stream_volume(payload)
            }
            (InterfaceValue::ServerData, FunctionId::OnChannelVolume) => {
                self.handle_on_channel_volume(payload)
            }
            (InterfaceValue::ServerData, FunctionId::SetVideoWindow) => {
                self.handle_set_video_window(payload)
            }
            (InterfaceValue::ServerData, FunctionId::UpdateGeometryInfo) => {
                self.handle_update_geometry_info(payload)
            }
            (InterfaceValue::ServerData, FunctionId::SetSourceVideoRect) => {
                self.handle_set_source_video_rect(payload)
            }
            (InterfaceValue::ServerData, FunctionId::SetAllocator) => {
                self.handle_set_allocator(payload)
            }
            // Unknown FunctionId on a known interface — ignore per spec §9.
            (InterfaceValue::ServerData, _) => Ok(Vec::new()),
            // Client Notifications interface PDUs are client→server only;
            // a server that sends one is buggy. Ignore rather than tear
            // down the channel.
            (InterfaceValue::ClientNotifications, _) => Ok(Vec::new()),
            // Unknown interface — ignore.
            _ => Ok(Vec::new()),
        }
    }

    // ── Step 3a handlers ──

    fn handle_exchange_capabilities_req(
        &mut self,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("EXCHANGE_CAPABILITIES_REQ")?;
        let mut r = ReadCursor::new(payload);
        let req = ExchangeCapabilitiesReq::decode(&mut r)?;
        let client_caps = self.sink.exchange_capabilities(&req.capabilities);
        let rsp = ExchangeCapabilitiesRsp::new(req.message_id, client_caps, S_OK);
        Ok(alloc::vec![Self::encode_pdu(&rsp)?])
    }

    fn handle_set_channel_params(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("SET_CHANNEL_PARAMS")?;
        let mut r = ReadCursor::new(payload);
        let req = SetChannelParams::decode(&mut r)?;
        if self.bind.is_some() {
            // Per spec §3.3.5.1, SET_CHANNEL_PARAMS is the FIRST
            // message on a fresh channel and must not repeat. A
            // repeat is a protocol violation.
            return Err(DvcError::Protocol(String::from(
                "MS-RDPEV: SET_CHANNEL_PARAMS received after channel was already bound",
            )));
        }
        self.bind = Some(ChannelBind {
            presentation_id: req.presentation_id,
            stream_id: req.stream_id,
        });
        // SET_CHANNEL_PARAMS is fire-and-forget; no response.
        Ok(Vec::new())
    }

    fn handle_on_new_presentation(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("ON_NEW_PRESENTATION")?;
        let mut r = ReadCursor::new(payload);
        let req = OnNewPresentation::decode(&mut r)?;
        if self.presentations.len() >= MAX_PRESENTATIONS
            && !self.presentations.contains_key(&req.presentation_id.0)
        {
            return Err(DvcError::Protocol(format!(
                "MS-RDPEV: too many concurrent presentations (cap = {MAX_PRESENTATIONS})"
            )));
        }
        // Hand off to the sink first; if it refuses, do not insert.
        match self
            .sink
            .on_new_presentation(req.presentation_id, req.platform_cookie)
        {
            Ok(()) => {
                self.presentations.insert(
                    req.presentation_id.0,
                    PresentationContext::new(req.platform_cookie),
                );
            }
            Err(_) => {
                // Sink refused -- do not insert. The spec has no
                // response PDU for ON_NEW_PRESENTATION, so the
                // failure is silent on the wire; subsequent PDUs for
                // this presentation will fail at the dispatch layer.
            }
        }
        Ok(Vec::new())
    }

    fn handle_check_format_support_req(
        &mut self,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("CHECK_FORMAT_SUPPORT_REQ")?;
        let mut r = ReadCursor::new(payload);
        let req = CheckFormatSupportReq::decode(&mut r)?;
        // The bind tells us which presentation the format query is
        // about. If the channel has not been bound yet, we still
        // dispatch the call to the sink with NIL so a misbehaving
        // server gets a clean answer rather than a tear-down.
        let presentation_id = self
            .bind
            .map(|b| b.presentation_id)
            .unwrap_or(Guid::NIL);
        let result: CheckFormatResult = self.sink.check_format_support(
            presentation_id,
            &req.media_type,
            req.platform_cookie,
            req.no_rollover_flags != 0,
        );
        let rsp = CheckFormatSupportRsp {
            message_id: req.message_id,
            format_supported: if result.supported { 1 } else { 0 },
            platform_cookie: result.platform_cookie,
            result: S_OK,
        };
        Ok(alloc::vec![Self::encode_pdu(&rsp)?])
    }

    // ── Step 3b handlers: presentation lifecycle ──

    fn handle_add_stream(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("ADD_STREAM")?;
        let mut r = ReadCursor::new(payload);
        let req = AddStream::decode(&mut r)?;
        let pres = match self.presentations.get_mut(&req.presentation_id.0) {
            Some(p) => p,
            None => {
                // Unknown presentation: hand the call to the sink
                // anyway (so a host that maintains its own routing
                // can still see the stream) and drop. We do not tear
                // the channel down because the spec is liberal here.
                let _ = self
                    .sink
                    .add_stream(req.presentation_id, req.stream_id, &req.media_type);
                return Ok(Vec::new());
            }
        };
        if pres.streams.len() >= MAX_STREAMS_PER_PRESENTATION
            && !pres.streams.contains_key(&req.stream_id)
        {
            return Err(DvcError::Protocol(format!(
                "MS-RDPEV: ADD_STREAM exceeds MAX_STREAMS_PER_PRESENTATION ({MAX_STREAMS_PER_PRESENTATION})"
            )));
        }
        match self
            .sink
            .add_stream(req.presentation_id, req.stream_id, &req.media_type)
        {
            Ok(()) => {
                pres.streams.insert(
                    req.stream_id,
                    StreamContext {
                        media_type: req.media_type.clone(),
                        state: StreamState::Added,
                    },
                );
                pres.state = PresentationState::Setup;
            }
            Err(_) => {
                // Sink refused; do not insert. No wire response.
            }
        }
        Ok(Vec::new())
    }

    fn handle_set_topology_req(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("SET_TOPOLOGY_REQ")?;
        let mut r = ReadCursor::new(payload);
        let req = SetTopologyReq::decode(&mut r)?;
        let ready = self.sink.set_topology(req.presentation_id);
        if let Some(pres) = self.presentations.get_mut(&req.presentation_id.0) {
            if ready {
                pres.state = PresentationState::Ready;
            }
        }
        let rsp = SetTopologyRsp {
            message_id: req.message_id,
            topology_ready: if ready { 1 } else { 0 },
            // Spec §2.2.5.2.6: Result = S_OK on success; for failure
            // the topology_ready flag does the heavy lifting and the
            // server treats E_FAIL identically. We pick S_OK so a
            // confused server still gets a parseable HRESULT.
            result: S_OK,
        };
        Ok(alloc::vec![Self::encode_pdu(&rsp)?])
    }

    fn handle_remove_stream(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("REMOVE_STREAM")?;
        let mut r = ReadCursor::new(payload);
        let req = RemoveStream::decode(&mut r)?;
        if let Some(pres) = self.presentations.get_mut(&req.presentation_id.0) {
            pres.streams.remove(&req.stream_id);
        }
        self.sink.remove_stream(req.presentation_id, req.stream_id);
        Ok(Vec::new())
    }

    fn handle_shutdown_presentation_req(
        &mut self,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("SHUTDOWN_PRESENTATION_REQ")?;
        let mut r = ReadCursor::new(payload);
        let req = ShutdownPresentationReq::decode(&mut r)?;
        // Mark Terminated briefly so observers see the transition,
        // then drop the entire context. The sink call must happen
        // BEFORE the map removal so the sink can still observe the
        // streams via its own bookkeeping if it wants to.
        if let Some(pres) = self.presentations.get_mut(&req.presentation_id.0) {
            pres.state = PresentationState::Terminated;
        }
        let result = self.sink.shutdown_presentation(req.presentation_id);
        self.presentations.remove(&req.presentation_id.0);
        let rsp = ShutdownPresentationRsp {
            message_id: req.message_id,
            result: result_to_hresult(result),
        };
        Ok(alloc::vec![Self::encode_pdu(&rsp)?])
    }

    // ── Step 3b handlers: ON_SAMPLE hot path ──

    fn handle_on_sample(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("ON_SAMPLE")?;
        let mut r = ReadCursor::new(payload);
        let req = OnSample::decode(&mut r)?;

        // Update internal stream state if the stream is known. We do
        // NOT bail out on unknown streams: spec §3.3.5.3.3 requires a
        // PLAYBACK_ACK for every ON_SAMPLE the client received, full
        // stop. The sink's handler is responsible for absorbing the
        // sample (or discarding it if unknown).
        if let Some(pres) = self.presentations.get_mut(&req.presentation_id.0) {
            if let Some(stream) = pres.streams.get_mut(&req.stream_id) {
                stream.state = StreamState::Streaming;
            }
        }
        // Capture echo fields BEFORE handing the sample to the sink
        // so we don't have to clone the whole payload.
        let echo_throttle = req.sample.throttle_duration;
        let echo_cb_data = req.sample.p_data.len() as u64;

        self.sink
            .on_sample(req.presentation_id, req.stream_id, &req.sample);

        let ack = PlaybackAck {
            message_id: self.next_msg_id(),
            stream_id: req.stream_id,
            data_duration: echo_throttle,
            cb_data: echo_cb_data,
        };
        Ok(alloc::vec![Self::encode_pdu(&ack)?])
    }

    // ── Step 3b handlers: playback control (fire-and-forget) ──

    fn handle_notify_preroll(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("NOTIFY_PREROLL")?;
        // NOTIFY_PREROLL is a buffering hint that the spec calls
        // RECOMMENDED rather than MUST; the sink trait deliberately
        // has no dedicated method for it. We still decode the PDU to
        // validate its structure (so a malformed prefix tears the
        // channel down rather than going unnoticed) but we do not
        // route it to the sink.
        let _ = NotifyPreroll::decode(&mut ReadCursor::new(payload))?;
        Ok(Vec::new())
    }

    fn handle_on_flush(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("ON_FLUSH")?;
        let req = OnFlush::decode(&mut ReadCursor::new(payload))?;
        self.sink.on_flush(req.presentation_id, req.stream_id);
        Ok(Vec::new())
    }

    fn handle_on_end_of_stream(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("ON_END_OF_STREAM")?;
        let req = OnEndOfStream::decode(&mut ReadCursor::new(payload))?;
        self.sink
            .on_end_of_stream(req.presentation_id, req.stream_id);
        Ok(Vec::new())
    }

    fn handle_on_playback_started(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("ON_PLAYBACK_STARTED")?;
        let req = OnPlaybackStarted::decode(&mut ReadCursor::new(payload))?;
        self.sink.on_playback_started(
            req.presentation_id,
            req.playback_start_offset,
            req.is_seek != 0,
        );
        Ok(Vec::new())
    }

    fn handle_on_playback_paused(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("ON_PLAYBACK_PAUSED")?;
        let req = OnPlaybackPaused::decode(&mut ReadCursor::new(payload))?;
        self.sink.on_playback_paused(req.presentation_id);
        Ok(Vec::new())
    }

    fn handle_on_playback_stopped(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("ON_PLAYBACK_STOPPED")?;
        let req = OnPlaybackStopped::decode(&mut ReadCursor::new(payload))?;
        self.sink.on_playback_stopped(req.presentation_id);
        Ok(Vec::new())
    }

    fn handle_on_playback_restarted(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("ON_PLAYBACK_RESTARTED")?;
        let req = OnPlaybackRestarted::decode(&mut ReadCursor::new(payload))?;
        self.sink.on_playback_restarted(req.presentation_id);
        Ok(Vec::new())
    }

    fn handle_on_playback_rate_changed(
        &mut self,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("ON_PLAYBACK_RATE_CHANGED")?;
        let req = OnPlaybackRateChanged::decode(&mut ReadCursor::new(payload))?;
        self.sink
            .on_playback_rate_changed(req.presentation_id, req.new_rate);
        Ok(Vec::new())
    }

    // ── Step 3b handlers: volume + geometry + window + allocator ──

    fn handle_on_stream_volume(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("ON_STREAM_VOLUME")?;
        let req = OnStreamVolume::decode(&mut ReadCursor::new(payload))?;
        self.sink
            .on_stream_volume(req.presentation_id, req.new_volume, req.b_muted != 0);
        Ok(Vec::new())
    }

    fn handle_on_channel_volume(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("ON_CHANNEL_VOLUME")?;
        let req = OnChannelVolume::decode(&mut ReadCursor::new(payload))?;
        self.sink.on_channel_volume(
            req.presentation_id,
            req.channel_volume,
            req.changed_channel,
        );
        Ok(Vec::new())
    }

    fn handle_set_video_window(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("SET_VIDEO_WINDOW")?;
        let req = SetVideoWindow::decode(&mut ReadCursor::new(payload))?;
        self.sink.set_video_window(
            req.presentation_id,
            req.video_window_id,
            req.hwnd_parent,
        );
        Ok(Vec::new())
    }

    fn handle_update_geometry_info(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("UPDATE_GEOMETRY_INFO")?;
        let req = UpdateGeometryInfo::decode(&mut ReadCursor::new(payload))?;
        self.sink
            .update_geometry(req.presentation_id, &req.geometry, &req.visible_rects);
        Ok(Vec::new())
    }

    fn handle_set_source_video_rect(
        &mut self,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("SET_SOURCE_VIDEO_RECT")?;
        let req = SetSourceVideoRect::decode(&mut ReadCursor::new(payload))?;
        self.sink.set_source_video_rect(
            req.presentation_id,
            req.left,
            req.top,
            req.right,
            req.bottom,
        );
        Ok(Vec::new())
    }

    fn handle_set_allocator(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.ensure_open("SET_ALLOCATOR")?;
        let req = SetAllocator::decode(&mut ReadCursor::new(payload))?;
        self.sink.set_allocator(
            req.presentation_id,
            req.stream_id,
            req.c_buffers,
            req.cb_buffer,
            req.cb_align,
            req.cb_prefix,
        );
        Ok(Vec::new())
    }

    // ── Step 3b: outbound ClientEventNotification helper ──

    /// Emits a `CLIENT_EVENT_NOTIFICATION` PDU on the Client
    /// Notifications interface. The host calls this to push
    /// application-defined events back to the server. Returns the
    /// encoded `DvcMessage` so the embedder can hand it to the DVC
    /// framework's send queue.
    pub fn client_event(
        &mut self,
        stream_id: u32,
        event_id: u32,
        blob: Vec<u8>,
    ) -> DvcResult<DvcMessage> {
        let pdu = ClientEventNotification {
            message_id: self.next_msg_id(),
            stream_id,
            event_id,
            p_blob: blob,
        };
        Self::encode_pdu(&pdu)
    }
}

// ── DvcProcessor impl ───────────────────────────────────────────────

impl DvcProcessor for RdpevClient {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        self.channel_id = channel_id;
        self.state = ChannelState::Initialised;
        // No client-originated PDU on channel open; the server drives
        // everything starting with SET_CHANNEL_PARAMS.
        Ok(Vec::new())
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if self.state == ChannelState::Closed {
            return Err(DvcError::Protocol(String::from(
                "MS-RDPEV: process() after close()",
            )));
        }
        self.dispatch(payload)
    }

    fn close(&mut self, _channel_id: u32) {
        self.state = ChannelState::Closed;
        self.presentations.clear();
        self.bind = None;
    }
}

impl AsAny for RdpevClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{capability_type, platform_cookie};
    use crate::media::{CheckFormatResult, MockTsmfMediaSink, TsmfError};
    use crate::pdu::capabilities::TsmmCapabilities;
    use crate::pdu::format::TsAmMediaType;

    const CHAN_ID: u32 = 7;

    const G1: Guid = Guid([
        0x9f, 0x04, 0x86, 0xe0, 0x26, 0xd9, 0xae, 0x45, 0x8c, 0x0f, 0x3e, 0x05, 0x6a, 0xf3, 0xf7,
        0xd4,
    ]);

    fn dummy_media_type() -> TsAmMediaType {
        TsAmMediaType {
            major_type: Guid([0x11; 16]),
            sub_type: Guid([0x22; 16]),
            b_fixed_size_samples: 0,
            b_temporal_compression: 1,
            sample_size: 0,
            format_type: Guid([0x33; 16]),
            pb_format: alloc::vec::Vec::new(),
        }
    }

    fn encode<T: Encode>(pdu: &T) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        buf
    }

    fn fresh_client() -> RdpevClient {
        let sink = Box::new(MockTsmfMediaSink::new());
        let mut c = RdpevClient::new(sink);
        c.start(CHAN_ID).unwrap();
        c
    }

    #[test]
    fn channel_name_is_tsmf() {
        let c = fresh_client();
        assert_eq!(c.channel_name(), "TSMF");
    }

    #[test]
    fn fresh_client_starts_in_uninitialised() {
        let c = RdpevClient::new(Box::new(MockTsmfMediaSink::new()));
        assert!(!c.is_open());
        assert_eq!(c.presentation_count(), 0);
        assert_eq!(c.bound_presentation(), None);
    }

    #[test]
    fn start_moves_to_initialised_with_no_messages() {
        let mut c = RdpevClient::new(Box::new(MockTsmfMediaSink::new()));
        let out = c.start(CHAN_ID).unwrap();
        assert!(out.is_empty());
        assert!(c.is_open());
    }

    #[test]
    fn process_before_start_is_protocol_error() {
        let mut c = RdpevClient::new(Box::new(MockTsmfMediaSink::new()));
        let req = SetChannelParams {
            message_id: 0,
            presentation_id: G1,
            stream_id: 0,
        };
        let bytes = encode(&req);
        let r = c.process(CHAN_ID, &bytes);
        assert!(matches!(r, Err(DvcError::Protocol(_))));
    }

    #[test]
    fn close_clears_state_and_blocks_further_process() {
        let mut c = fresh_client();
        c.close(CHAN_ID);
        assert!(!c.is_open());
        assert_eq!(c.presentation_count(), 0);
        let req = SetChannelParams {
            message_id: 0,
            presentation_id: G1,
            stream_id: 0,
        };
        let bytes = encode(&req);
        assert!(matches!(
            c.process(CHAN_ID, &bytes),
            Err(DvcError::Protocol(_))
        ));
    }

    // ── EXCHANGE_CAPABILITIES_REQ ──

    #[test]
    fn exchange_capabilities_req_emits_response_with_echoed_message_id() {
        let sink = Box::new(MockTsmfMediaSink::new().with_client_capabilities(alloc::vec![
            TsmmCapabilities::u32_payload(capability_type::VERSION, 0x02),
        ]));
        let mut c = RdpevClient::new(sink);
        c.start(CHAN_ID).unwrap();

        let req = ExchangeCapabilitiesReq::new(
            42,
            alloc::vec![TsmmCapabilities::u32_payload(capability_type::VERSION, 0x02)],
        );
        let bytes = encode(&req);
        let mut out = c.process(CHAN_ID, &bytes).unwrap();
        assert_eq!(out.len(), 1);

        let rsp_bytes = out.remove(0).data;
        let mut r = ReadCursor::new(&rsp_bytes);
        let rsp = ExchangeCapabilitiesRsp::decode(&mut r).unwrap();
        assert_eq!(rsp.message_id, 42);
        assert_eq!(rsp.result, S_OK);
        assert_eq!(rsp.capabilities.len(), 1);
        assert_eq!(
            rsp.capabilities[0].capability_type,
            capability_type::VERSION
        );
    }

    #[test]
    fn exchange_capabilities_passes_server_caps_to_sink() {
        let mut c = fresh_client();
        let server_caps = alloc::vec![
            TsmmCapabilities::u32_payload(capability_type::VERSION, 0x02),
            TsmmCapabilities::u32_payload(capability_type::PLATFORM, 0x01),
        ];
        let req = ExchangeCapabilitiesReq::new(0, server_caps.clone());
        let bytes = encode(&req);
        c.process(CHAN_ID, &bytes).unwrap();

        let sink = c
            .sink
            .as_any()
            .downcast_ref::<MockTsmfMediaSink>()
            .unwrap();
        assert_eq!(sink.exchange_capabilities_calls, 1);
        assert_eq!(sink.last_server_capabilities, server_caps);
    }

    // ── SET_CHANNEL_PARAMS ──

    #[test]
    fn set_channel_params_binds_channel_and_emits_no_response() {
        let mut c = fresh_client();
        let req = SetChannelParams {
            message_id: 0,
            presentation_id: G1,
            stream_id: 0,
        };
        let bytes = encode(&req);
        let out = c.process(CHAN_ID, &bytes).unwrap();
        assert!(out.is_empty());
        assert_eq!(c.bound_presentation(), Some(G1));
    }

    #[test]
    fn second_set_channel_params_is_protocol_violation() {
        let mut c = fresh_client();
        let req = SetChannelParams {
            message_id: 0,
            presentation_id: G1,
            stream_id: 0,
        };
        let bytes = encode(&req);
        c.process(CHAN_ID, &bytes).unwrap();
        // Same again must fail per spec §3.3.5.1.
        assert!(matches!(
            c.process(CHAN_ID, &bytes),
            Err(DvcError::Protocol(_))
        ));
    }

    // ── ON_NEW_PRESENTATION ──

    #[test]
    fn on_new_presentation_inserts_context_when_sink_accepts() {
        let mut c = fresh_client();
        let req = OnNewPresentation {
            message_id: 0,
            presentation_id: G1,
            platform_cookie: platform_cookie::DSHOW,
        };
        let bytes = encode(&req);
        let out = c.process(CHAN_ID, &bytes).unwrap();
        assert!(out.is_empty());
        assert_eq!(c.presentation_count(), 1);

        let sink = c
            .sink
            .as_any()
            .downcast_ref::<MockTsmfMediaSink>()
            .unwrap();
        assert_eq!(sink.on_new_presentation_calls, 1);
        assert_eq!(
            sink.last_new_presentation,
            Some((G1, platform_cookie::DSHOW))
        );
    }

    #[test]
    fn on_new_presentation_skips_insert_when_sink_refuses() {
        let sink = Box::new(MockTsmfMediaSink::new().fail_new_presentation_with(TsmfError::OutOfMemory));
        let mut c = RdpevClient::new(sink);
        c.start(CHAN_ID).unwrap();
        let req = OnNewPresentation {
            message_id: 0,
            presentation_id: G1,
            platform_cookie: platform_cookie::MF,
        };
        let bytes = encode(&req);
        c.process(CHAN_ID, &bytes).unwrap();
        // Sink was called, but the presentation map is still empty.
        assert_eq!(c.presentation_count(), 0);
    }

    #[test]
    fn on_new_presentation_enforces_max_presentations_cap() {
        let mut c = fresh_client();
        for i in 0..MAX_PRESENTATIONS as u8 {
            let mut g = [0u8; 16];
            g[0] = i;
            let req = OnNewPresentation {
                message_id: 0,
                presentation_id: Guid(g),
                platform_cookie: 0,
            };
            let bytes = encode(&req);
            c.process(CHAN_ID, &bytes).unwrap();
        }
        // One more — must be rejected.
        let mut g = [0u8; 16];
        g[0] = 0xFF;
        let req = OnNewPresentation {
            message_id: 0,
            presentation_id: Guid(g),
            platform_cookie: 0,
        };
        let bytes = encode(&req);
        assert!(matches!(
            c.process(CHAN_ID, &bytes),
            Err(DvcError::Protocol(_))
        ));
    }

    // ── CHECK_FORMAT_SUPPORT_REQ ──

    #[test]
    fn check_format_support_req_emits_supported_response() {
        let sink = Box::new(
            MockTsmfMediaSink::new()
                .with_format_response(CheckFormatResult::supported(platform_cookie::MF)),
        );
        let mut c = RdpevClient::new(sink);
        c.start(CHAN_ID).unwrap();

        let req = CheckFormatSupportReq {
            message_id: 99,
            platform_cookie: platform_cookie::MF,
            no_rollover_flags: 0,
            media_type: dummy_media_type(),
        };
        let bytes = encode(&req);
        let mut out = c.process(CHAN_ID, &bytes).unwrap();
        assert_eq!(out.len(), 1);
        let rsp_bytes = out.remove(0).data;
        let mut r = ReadCursor::new(&rsp_bytes);
        let rsp = CheckFormatSupportRsp::decode(&mut r).unwrap();
        assert_eq!(rsp.message_id, 99);
        assert_eq!(rsp.format_supported, 1);
        assert_eq!(rsp.platform_cookie, platform_cookie::MF);
        assert_eq!(rsp.result, S_OK);
    }

    #[test]
    fn check_format_support_req_emits_unsupported_response() {
        let sink = Box::new(
            MockTsmfMediaSink::new().with_format_response(CheckFormatResult::unsupported()),
        );
        let mut c = RdpevClient::new(sink);
        c.start(CHAN_ID).unwrap();
        let req = CheckFormatSupportReq {
            message_id: 0,
            platform_cookie: platform_cookie::MF,
            no_rollover_flags: 1,
            media_type: dummy_media_type(),
        };
        let bytes = encode(&req);
        let mut out = c.process(CHAN_ID, &bytes).unwrap();
        let rsp_bytes = out.remove(0).data;
        let mut r = ReadCursor::new(&rsp_bytes);
        let rsp = CheckFormatSupportRsp::decode(&mut r).unwrap();
        assert_eq!(rsp.format_supported, 0);
    }

    // ── Step 3b: presentation lifecycle ──

    fn create_presentation(c: &mut RdpevClient, g: Guid) {
        let req = OnNewPresentation {
            message_id: 0,
            presentation_id: g,
            platform_cookie: platform_cookie::MF,
        };
        c.process(CHAN_ID, &encode(&req)).unwrap();
    }

    fn add_stream(c: &mut RdpevClient, g: Guid, stream_id: u32) {
        let req = AddStream {
            message_id: 0,
            presentation_id: g,
            stream_id,
            media_type: dummy_media_type(),
        };
        c.process(CHAN_ID, &encode(&req)).unwrap();
    }

    fn sink_of(c: &RdpevClient) -> &MockTsmfMediaSink {
        c.sink
            .as_any()
            .downcast_ref::<MockTsmfMediaSink>()
            .unwrap()
    }

    #[test]
    fn add_stream_inserts_stream_and_transitions_to_setup() {
        let mut c = fresh_client();
        create_presentation(&mut c, G1);
        add_stream(&mut c, G1, 7);
        let pres = c.presentations.get(&G1.0).unwrap();
        assert_eq!(pres.state, PresentationState::Setup);
        assert!(pres.streams.contains_key(&7));
        assert_eq!(pres.streams[&7].state, StreamState::Added);
        assert_eq!(sink_of(&c).add_stream_calls, 1);
    }

    #[test]
    fn add_stream_for_unknown_presentation_still_calls_sink_but_no_insert() {
        let mut c = fresh_client();
        // Skip create_presentation deliberately.
        add_stream(&mut c, G1, 1);
        assert_eq!(c.presentation_count(), 0);
        // Sink was still called per the liberal-receiver policy.
        assert_eq!(sink_of(&c).add_stream_calls, 1);
    }

    #[test]
    fn add_stream_skips_insert_when_sink_refuses() {
        let sink = Box::new(
            MockTsmfMediaSink::new().fail_add_stream_with(TsmfError::OperationNotSupported),
        );
        let mut c = RdpevClient::new(sink);
        c.start(CHAN_ID).unwrap();
        create_presentation(&mut c, G1);
        add_stream(&mut c, G1, 1);
        let pres = c.presentations.get(&G1.0).unwrap();
        assert!(pres.streams.is_empty());
        // Presentation stays in Created (no successful ADD_STREAM yet).
        assert_eq!(pres.state, PresentationState::Created);
    }

    #[test]
    fn add_stream_enforces_max_streams_per_presentation_cap() {
        let mut c = fresh_client();
        create_presentation(&mut c, G1);
        for sid in 0..MAX_STREAMS_PER_PRESENTATION as u32 {
            add_stream(&mut c, G1, sid);
        }
        // One more — must be rejected.
        let req = AddStream {
            message_id: 0,
            presentation_id: G1,
            stream_id: 999,
            media_type: dummy_media_type(),
        };
        assert!(matches!(
            c.process(CHAN_ID, &encode(&req)),
            Err(DvcError::Protocol(_))
        ));
    }

    #[test]
    fn set_topology_req_emits_rsp_with_ready_flag_and_transitions_to_ready() {
        let mut c = fresh_client();
        create_presentation(&mut c, G1);
        add_stream(&mut c, G1, 0);
        let req = SetTopologyReq {
            message_id: 17,
            presentation_id: G1,
        };
        let mut out = c.process(CHAN_ID, &encode(&req)).unwrap();
        assert_eq!(out.len(), 1);
        let rsp = SetTopologyRsp::decode(&mut ReadCursor::new(&out.remove(0).data)).unwrap();
        assert_eq!(rsp.message_id, 17);
        assert_eq!(rsp.topology_ready, 1);
        assert_eq!(rsp.result, S_OK);
        let pres = c.presentations.get(&G1.0).unwrap();
        assert_eq!(pres.state, PresentationState::Ready);
    }

    #[test]
    fn set_topology_req_returns_not_ready_when_sink_refuses() {
        let sink = Box::new(MockTsmfMediaSink::new().with_topology_ready(false));
        let mut c = RdpevClient::new(sink);
        c.start(CHAN_ID).unwrap();
        create_presentation(&mut c, G1);
        let req = SetTopologyReq {
            message_id: 0,
            presentation_id: G1,
        };
        let mut out = c.process(CHAN_ID, &encode(&req)).unwrap();
        let rsp = SetTopologyRsp::decode(&mut ReadCursor::new(&out.remove(0).data)).unwrap();
        assert_eq!(rsp.topology_ready, 0);
        // State stays in Created (not promoted to Ready).
        assert_eq!(
            c.presentations.get(&G1.0).unwrap().state,
            PresentationState::Created
        );
    }

    // ── ON_SAMPLE → PLAYBACK_ACK hot path ──

    fn dummy_sample(throttle: u64, p_data: Vec<u8>) -> crate::pdu::sample::TsMmDataSample {
        crate::pdu::sample::TsMmDataSample {
            sample_start_time: 100,
            sample_end_time: 200,
            throttle_duration: throttle,
            sample_flags: 0,
            sample_extensions: 0,
            p_data,
        }
    }

    #[test]
    fn on_sample_emits_playback_ack_with_echoed_fields() {
        let mut c = fresh_client();
        create_presentation(&mut c, G1);
        add_stream(&mut c, G1, 1);

        let req = OnSample {
            message_id: 0,
            presentation_id: G1,
            stream_id: 1,
            sample: dummy_sample(0xCAFE, alloc::vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00]),
        };
        let mut out = c.process(CHAN_ID, &encode(&req)).unwrap();
        assert_eq!(out.len(), 1);
        let ack = PlaybackAck::decode(&mut ReadCursor::new(&out.remove(0).data)).unwrap();
        assert_eq!(ack.stream_id, 1);
        assert_eq!(ack.data_duration, 0xCAFE);
        assert_eq!(ack.cb_data, 5);

        // Stream state promoted to Streaming.
        assert_eq!(
            c.presentations.get(&G1.0).unwrap().streams[&1].state,
            StreamState::Streaming
        );
        let s = sink_of(&c);
        assert_eq!(s.on_sample_calls, 1);
        let (gid, sid, payload) = s.last_sample.as_ref().unwrap();
        assert_eq!(*gid, G1);
        assert_eq!(*sid, 1);
        assert_eq!(payload, &alloc::vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00]);
    }

    #[test]
    fn on_sample_for_unknown_presentation_still_emits_ack() {
        // 1:1 ack rule applies regardless of whether the client knew
        // the stream. The host is responsible for absorbing samples
        // it does not recognise.
        let mut c = fresh_client();
        let req = OnSample {
            message_id: 0,
            presentation_id: G1, // never created
            stream_id: 1,
            sample: dummy_sample(7, alloc::vec![]),
        };
        let mut out = c.process(CHAN_ID, &encode(&req)).unwrap();
        assert_eq!(out.len(), 1);
        let ack = PlaybackAck::decode(&mut ReadCursor::new(&out.remove(0).data)).unwrap();
        assert_eq!(ack.stream_id, 1);
        assert_eq!(ack.data_duration, 7);
        assert_eq!(ack.cb_data, 0);
        // Sink still saw it.
        assert_eq!(sink_of(&c).on_sample_calls, 1);
    }

    #[test]
    fn playback_ack_message_ids_are_monotonic_across_samples() {
        let mut c = fresh_client();
        create_presentation(&mut c, G1);
        add_stream(&mut c, G1, 0);
        let mut last_id = None;
        for _ in 0..3 {
            let req = OnSample {
                message_id: 0,
                presentation_id: G1,
                stream_id: 0,
                sample: dummy_sample(0, alloc::vec![]),
            };
            let mut out = c.process(CHAN_ID, &encode(&req)).unwrap();
            let ack = PlaybackAck::decode(&mut ReadCursor::new(&out.remove(0).data)).unwrap();
            if let Some(prev) = last_id {
                assert!(ack.message_id > prev, "expected monotonic ids");
            }
            last_id = Some(ack.message_id);
        }
    }

    // ── REMOVE_STREAM + SHUTDOWN_PRESENTATION_REQ ──

    #[test]
    fn remove_stream_drops_stream_and_calls_sink() {
        let mut c = fresh_client();
        create_presentation(&mut c, G1);
        add_stream(&mut c, G1, 0);
        add_stream(&mut c, G1, 1);
        let req = RemoveStream {
            message_id: 0,
            presentation_id: G1,
            stream_id: 0,
        };
        let out = c.process(CHAN_ID, &encode(&req)).unwrap();
        assert!(out.is_empty());
        let pres = c.presentations.get(&G1.0).unwrap();
        assert!(!pres.streams.contains_key(&0));
        assert!(pres.streams.contains_key(&1));
        assert_eq!(sink_of(&c).remove_stream_calls, 1);
    }

    #[test]
    fn shutdown_presentation_req_removes_presentation_and_emits_rsp() {
        let mut c = fresh_client();
        create_presentation(&mut c, G1);
        add_stream(&mut c, G1, 0);
        let req = ShutdownPresentationReq {
            message_id: 55,
            presentation_id: G1,
        };
        let mut out = c.process(CHAN_ID, &encode(&req)).unwrap();
        assert_eq!(out.len(), 1);
        let rsp = ShutdownPresentationRsp::decode(&mut ReadCursor::new(&out.remove(0).data))
            .unwrap();
        assert_eq!(rsp.message_id, 55);
        assert_eq!(rsp.result, S_OK);
        assert_eq!(c.presentation_count(), 0);
        assert_eq!(sink_of(&c).shutdown_presentation_calls, 1);
    }

    #[test]
    fn shutdown_presentation_returns_sink_error_as_hresult() {
        let sink = Box::new(
            MockTsmfMediaSink::new().fail_shutdown_with(TsmfError::OperationNotSupported),
        );
        let mut c = RdpevClient::new(sink);
        c.start(CHAN_ID).unwrap();
        create_presentation(&mut c, G1);
        let req = ShutdownPresentationReq {
            message_id: 0,
            presentation_id: G1,
        };
        let mut out = c.process(CHAN_ID, &encode(&req)).unwrap();
        let rsp = ShutdownPresentationRsp::decode(&mut ReadCursor::new(&out.remove(0).data))
            .unwrap();
        // E_NOTIMPL = 0x80004001
        assert_eq!(rsp.result, 0x8000_4001);
        // The presentation is removed even on sink failure.
        assert_eq!(c.presentation_count(), 0);
    }

    // ── Playback control fire-and-forget ──

    #[test]
    fn control_pdus_dispatch_to_correct_sink_methods() {
        let mut c = fresh_client();
        create_presentation(&mut c, G1);
        add_stream(&mut c, G1, 0);

        // OnFlush
        c.process(
            CHAN_ID,
            &encode(&OnFlush {
                message_id: 0,
                presentation_id: G1,
                stream_id: 0,
            }),
        )
        .unwrap();
        // OnEndOfStream
        c.process(
            CHAN_ID,
            &encode(&OnEndOfStream {
                message_id: 0,
                presentation_id: G1,
                stream_id: 0,
            }),
        )
        .unwrap();
        // OnPlaybackStarted
        c.process(
            CHAN_ID,
            &encode(&OnPlaybackStarted {
                message_id: 0,
                presentation_id: G1,
                playback_start_offset: 10_000,
                is_seek: 1,
            }),
        )
        .unwrap();
        // OnPlaybackPaused / Stopped / Restarted
        c.process(
            CHAN_ID,
            &encode(&OnPlaybackPaused {
                message_id: 0,
                presentation_id: G1,
            }),
        )
        .unwrap();
        c.process(
            CHAN_ID,
            &encode(&OnPlaybackStopped {
                message_id: 0,
                presentation_id: G1,
            }),
        )
        .unwrap();
        c.process(
            CHAN_ID,
            &encode(&OnPlaybackRestarted {
                message_id: 0,
                presentation_id: G1,
            }),
        )
        .unwrap();
        c.process(
            CHAN_ID,
            &encode(&OnPlaybackRateChanged {
                message_id: 0,
                presentation_id: G1,
                new_rate: 1.5,
            }),
        )
        .unwrap();
        // NotifyPreroll — decoded but not routed to sink.
        c.process(
            CHAN_ID,
            &encode(&NotifyPreroll {
                message_id: 0,
                presentation_id: G1,
                stream_id: 0,
            }),
        )
        .unwrap();

        let s = sink_of(&c);
        assert_eq!(s.on_flush_calls, 1);
        assert_eq!(s.on_end_of_stream_calls, 1);
        assert_eq!(s.on_playback_started_calls, 1);
        assert_eq!(s.on_playback_paused_calls, 1);
        assert_eq!(s.on_playback_stopped_calls, 1);
        assert_eq!(s.on_playback_restarted_calls, 1);
        assert_eq!(s.on_playback_rate_changed_calls, 1);
    }

    #[test]
    fn volume_geometry_window_allocator_dispatch() {
        use crate::pdu::geometry::{GeometryInfo, TsRect};
        let mut c = fresh_client();
        create_presentation(&mut c, G1);
        add_stream(&mut c, G1, 0);

        c.process(
            CHAN_ID,
            &encode(&OnStreamVolume {
                message_id: 0,
                presentation_id: G1,
                new_volume: 100,
                b_muted: 0,
            }),
        )
        .unwrap();
        c.process(
            CHAN_ID,
            &encode(&OnChannelVolume {
                message_id: 0,
                presentation_id: G1,
                channel_volume: 50,
                changed_channel: 1,
            }),
        )
        .unwrap();
        c.process(
            CHAN_ID,
            &encode(&SetVideoWindow {
                message_id: 0,
                presentation_id: G1,
                video_window_id: 0xAA,
                hwnd_parent: 0xBB,
            }),
        )
        .unwrap();
        c.process(
            CHAN_ID,
            &encode(&UpdateGeometryInfo {
                message_id: 0,
                presentation_id: G1,
                geometry: GeometryInfo {
                    video_window_id: 0,
                    video_window_state: 0,
                    width: 1920,
                    height: 1080,
                    left: 0,
                    top: 0,
                    reserved: 0,
                    client_left: 0,
                    client_top: 0,
                    padding: None,
                },
                visible_rects: alloc::vec![TsRect {
                    top: 0,
                    left: 0,
                    bottom: 1080,
                    right: 1920,
                }],
            }),
        )
        .unwrap();
        c.process(
            CHAN_ID,
            &encode(&SetSourceVideoRect {
                message_id: 0,
                presentation_id: G1,
                left: 0.0,
                top: 0.0,
                right: 1.0,
                bottom: 1.0,
            }),
        )
        .unwrap();
        c.process(
            CHAN_ID,
            &encode(&SetAllocator {
                message_id: 0,
                presentation_id: G1,
                stream_id: 0,
                c_buffers: 4,
                cb_buffer: 4096,
                cb_align: 16,
                cb_prefix: 0,
            }),
        )
        .unwrap();

        let s = sink_of(&c);
        assert_eq!(s.on_stream_volume_calls, 1);
        assert_eq!(s.on_channel_volume_calls, 1);
        assert_eq!(s.set_video_window_calls, 1);
        assert_eq!(s.update_geometry_calls, 1);
        assert_eq!(s.set_source_video_rect_calls, 1);
        assert_eq!(s.set_allocator_calls, 1);
    }

    // ── Outbound ClientEventNotification helper ──

    #[test]
    fn client_event_helper_emits_valid_notification() {
        let mut c = fresh_client();
        let msg = c
            .client_event(7, 0xCAFE, alloc::vec![0xDE, 0xAD])
            .unwrap();
        let decoded =
            ClientEventNotification::decode(&mut ReadCursor::new(&msg.data)).unwrap();
        assert_eq!(decoded.stream_id, 7);
        assert_eq!(decoded.event_id, 0xCAFE);
        assert_eq!(decoded.p_blob, alloc::vec![0xDE, 0xAD]);
    }

    // ── Full happy-path end-to-end ──

    #[test]
    fn full_presentation_lifecycle_round_trip() {
        let mut c = fresh_client();
        // 1. Bind
        c.process(
            CHAN_ID,
            &encode(&SetChannelParams {
                message_id: 0,
                presentation_id: G1,
                stream_id: 0,
            }),
        )
        .unwrap();
        // 2. Capabilities
        let caps_out = c
            .process(
                CHAN_ID,
                &encode(&ExchangeCapabilitiesReq::new(
                    0,
                    alloc::vec![TsmmCapabilities::u32_payload(capability_type::VERSION, 2)],
                )),
            )
            .unwrap();
        assert_eq!(caps_out.len(), 1);
        // 3. ON_NEW_PRESENTATION
        create_presentation(&mut c, G1);
        // 4. CHECK_FORMAT_SUPPORT
        let fmt_out = c
            .process(
                CHAN_ID,
                &encode(&CheckFormatSupportReq {
                    message_id: 0,
                    platform_cookie: platform_cookie::MF,
                    no_rollover_flags: 0,
                    media_type: dummy_media_type(),
                }),
            )
            .unwrap();
        assert_eq!(fmt_out.len(), 1);
        // 5. ADD_STREAM
        add_stream(&mut c, G1, 0);
        // 6. SET_TOPOLOGY
        let topo_out = c
            .process(
                CHAN_ID,
                &encode(&SetTopologyReq {
                    message_id: 0,
                    presentation_id: G1,
                }),
            )
            .unwrap();
        assert_eq!(topo_out.len(), 1);
        assert_eq!(
            c.presentations.get(&G1.0).unwrap().state,
            PresentationState::Ready
        );
        // 7. ON_SAMPLE → PLAYBACK_ACK
        let sample_out = c
            .process(
                CHAN_ID,
                &encode(&OnSample {
                    message_id: 0,
                    presentation_id: G1,
                    stream_id: 0,
                    sample: dummy_sample(42, alloc::vec![1, 2, 3]),
                }),
            )
            .unwrap();
        assert_eq!(sample_out.len(), 1);
        // 8. SHUTDOWN
        c.process(
            CHAN_ID,
            &encode(&ShutdownPresentationReq {
                message_id: 0,
                presentation_id: G1,
            }),
        )
        .unwrap();
        assert_eq!(c.presentation_count(), 0);

        let s = sink_of(&c);
        assert_eq!(s.exchange_capabilities_calls, 1);
        assert_eq!(s.on_new_presentation_calls, 1);
        assert_eq!(s.check_format_support_calls, 1);
        assert_eq!(s.add_stream_calls, 1);
        assert_eq!(s.set_topology_calls, 1);
        assert_eq!(s.on_sample_calls, 1);
        assert_eq!(s.shutdown_presentation_calls, 1);
    }

    // ── Dispatch ──

    #[test]
    fn unknown_function_id_is_silently_ignored() {
        // Build a 12-byte PROXY header with an unknown FunctionId
        // (e.g. 0xDEAD_BEEF). Dispatch must return Ok(empty), not
        // an error -- spec §9 says ignore unknown.
        let bytes = [
            0x00, 0x00, 0x00, 0x40, // PROXY | ServerData
            0x00, 0x00, 0x00, 0x00, // MessageId
            0xEF, 0xBE, 0xAD, 0xDE, // FunctionId = 0xDEADBEEF
        ];
        let mut c = fresh_client();
        let out = c.process(CHAN_ID, &bytes).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn server_sent_stub_payload_is_protocol_error() {
        // STUB-masked PDUs are responses; the server must not send
        // them because the client is the responder.
        let bytes = [
            0x00, 0x00, 0x00, 0x80, // STUB
            0x00, 0x00, 0x00, 0x00, // MessageId
        ];
        let mut c = fresh_client();
        assert!(matches!(
            c.process(CHAN_ID, &bytes),
            Err(DvcError::Protocol(_))
        ));
    }

    #[test]
    fn short_payload_is_protocol_error() {
        let bytes = [0u8, 0u8, 0u8];
        let mut c = fresh_client();
        assert!(matches!(
            c.process(CHAN_ID, &bytes),
            Err(DvcError::Protocol(_))
        ));
    }
}
