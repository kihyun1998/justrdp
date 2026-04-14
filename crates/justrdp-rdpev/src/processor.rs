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
use crate::media::{CheckFormatResult, TsmfMediaSink};
use crate::pdu::capabilities::{ExchangeCapabilitiesReq, ExchangeCapabilitiesRsp};
use crate::pdu::format::{CheckFormatSupportReq, CheckFormatSupportRsp, TsAmMediaType};
use crate::pdu::guid::{Guid, GUID_SIZE};
use crate::pdu::presentation::{OnNewPresentation, SetChannelParams};
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

// PresentationState/StreamState/StreamContext fields are written in
// Step 3a (`Created`) and read by every subsequent transition that
// Step 3b will add (Setup → Ready → Terminated, Added → Streaming →
// Stopped). The dead_code allow keeps the public skeleton compiling
// cleanly until 3b lands.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PresentationState {
    Created,
    Setup,
    Ready,
    Terminated,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamState {
    Added,
    Streaming,
    Stopped,
}

// ── Per-presentation context ────────────────────────────────────────

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct StreamContext {
    pub media_type: TsAmMediaType,
    pub state: StreamState,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct PresentationContext {
    pub state: PresentationState,
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
            // ── Step 3a handlers ──
            (InterfaceValue::ServerData, FunctionId::ExchangeCapabilitiesReq) => {
                self.handle_exchange_capabilities_req(payload)
            }
            (InterfaceValue::ServerData, FunctionId::SetChannelParams) => {
                self.handle_set_channel_params(payload)
            }
            (InterfaceValue::ServerData, FunctionId::OnNewPresentation) => {
                self.handle_on_new_presentation(payload)
            }
            (InterfaceValue::ServerData, FunctionId::CheckFormatSupportReq) => {
                self.handle_check_format_support_req(payload)
            }
            // ── Step 3b handlers (deliberately unimplemented for now) ──
            (InterfaceValue::ServerData, _) => {
                // Step 3b will fill these in. For now: ignore so the
                // skeleton compiles cleanly and the partial-coverage
                // tests can exercise the four implemented paths.
                Ok(Vec::new())
            }
            // Unknown interface -- ignore.
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
