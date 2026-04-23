#![forbid(unsafe_code)]

//! `ServerActiveStage` -- post-`Accepted` session loop.
//!
//! This module implements the **server-side** half of the active RDP
//! session: it consumes complete client PDUs (TPKT-framed slow-path or
//! fast-path) and produces a stream of [`ActiveStageOutput`] events that
//! the caller routes to display / input handlers and to the network.
//!
//! Scope after Commit 8:
//!
//! | `pduType2`              | Value | Behaviour                                         |
//! |-------------------------|------:|---------------------------------------------------|
//! | `Refresh Rect`          |  0x21 | emit [`ActiveStageOutput::RefreshRect`]           |
//! | `Suppress Output`       |  0x23 | track `suppress_output`, emit notification        |
//! | `Shutdown Request`      |  0x24 | emit `ShutdownDenied` reply + notification        |
//! | `Control(RequestCtrl)`  |  0x14 | emit `GrantedControl` reply (FreeRDP-style)       |
//! | `Control(Detach)`       |  0x14 | emit [`ActiveStageOutput::ClientDetached`]        |
//! | `Persistent Key List`   |  0x2B | silent consume with DoS-cap                       |
//! | `Input` (slow-path)     |  0x1C | dispatch each TS_INPUT_EVENT to input handler     |
//! | other `pduType2`        |     ? | error                                             |
//!
//! Fast-path input PDUs are decoded (header + each `FastPathInputEvent`)
//! and dispatched to the input handler. SVC channel data is reassembled
//! across `CHANNEL_FLAG_FIRST` / `_LAST` chunks and surfaced as
//! [`ActiveStageOutput::SvcData`].

use alloc::vec;
use alloc::vec::Vec;

use justrdp_acceptor::AcceptanceResult;
use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_pdu::mcs::{
    DisconnectProviderUltimatum, DisconnectReason, SendDataIndication, SendDataRequest,
};
use justrdp_pdu::rdp::error_info::ErrorInfoCode;
use justrdp_pdu::rdp::finalization::SetErrorInfoPdu;
use justrdp_pdu::rdp::fast_path::{FastPathInputEvent, FastPathInputHeader};
use justrdp_pdu::rdp::finalization::{
    ControlAction, ControlPdu, InputEventPdu, InputEventType, PersistentKeyListPdu, RefreshRectPdu,
    ShutdownDeniedPdu, ShutdownRequestPdu, SuppressOutputPdu,
};
use justrdp_pdu::rdp::headers::{
    ShareControlHeader, ShareControlPduType, ShareDataHeader, ShareDataPduType,
    SHARE_CONTROL_HEADER_SIZE, SHARE_DATA_HEADER_SIZE,
};
use justrdp_pdu::rdp::svc::{
    ChannelPduHeader, CHANNEL_FLAG_FIRST, CHANNEL_FLAG_LAST, CHANNEL_PACKET_COMPRESSED,
    CHANNEL_PDU_HEADER_SIZE,
};
use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
use justrdp_pdu::x224::{DataTransfer, DATA_TRANSFER_HEADER_SIZE};

use crate::config::RdpServerConfig;
use crate::error::{ServerError, ServerResult};
use crate::handler::{DisplayRect, RdpServerInputHandler};

// ── Slow-path keyboard flags (MS-RDPBCGR §2.2.8.1.1.3.1.1.1) ──

const SLOW_PATH_KBDFLAGS_EXTENDED: u16 = 0x0100;
const SLOW_PATH_KBDFLAGS_EXTENDED1: u16 = 0x0200;
const SLOW_PATH_KBDFLAGS_RELEASE: u16 = 0x8000;

// ── Fast-path keyboard flag bits (MS-RDPBCGR §2.2.8.1.2.2.1) ──
//
// Re-exported here as constants because the translation
// `slow_path_kbd_flags_to_fast_path` needs them and the PDU crate does
// not export them as named symbols (they live as inline literals in
// the `event_flags & 0x1F` packing).

const FASTPATH_INPUT_KBDFLAGS_RELEASE: u16 = 0x0001;
const FASTPATH_INPUT_KBDFLAGS_EXTENDED: u16 = 0x0002;
const FASTPATH_INPUT_KBDFLAGS_EXTENDED1: u16 = 0x0004;

/// Wire size of a single slow-path TS_INPUT_EVENT record. All event
/// types currently defined (Synchronize, ScanCode, Unicode, Mouse,
/// ExtendedMouse) are 12 bytes total -- 6-byte header (`eventTime` u32
/// + `messageType` u16) plus 6 bytes of event-specific data including
/// any padding (MS-RDPBCGR §2.2.8.1.1.3.1.1).
const SLOW_PATH_INPUT_EVENT_SIZE: usize = 12;

/// Map a raw slow-path `messageType` (u16) to the typed enum
/// (MS-RDPBCGR §2.2.8.1.1.3.1.1), falling back to `Err(())` for
/// forward-compatibility values the server does not yet understand.
/// The slow-path input dispatcher treats `Err(())` as "skip this
/// event" rather than aborting the whole PDU.
fn decode_slow_path_message_type(raw: u16) -> Result<InputEventType, ()> {
    match raw {
        0x0000 => Ok(InputEventType::Synchronize),
        0x0004 => Ok(InputEventType::ScanCode),
        0x0005 => Ok(InputEventType::Unicode),
        0x8001 => Ok(InputEventType::Mouse),
        0x8002 => Ok(InputEventType::ExtendedMouse),
        _ => Err(()),
    }
}

/// Translate a slow-path `TS_KEYBOARD_EVENT.keyboardFlags` value
/// (MS-RDPBCGR §2.2.8.1.1.3.1.1.1) to the fast-path
/// `FASTPATH_INPUT_KBDFLAGS_*` bit layout (§2.2.8.1.2.2.1) so handlers
/// see one representation regardless of input path. `KBDFLAGS_DOWN` is
/// not represented in fast-path -- a key press is implied by the
/// absence of `_RELEASE`.
fn slow_path_kbd_flags_to_fast_path(slow: u16) -> u16 {
    let mut out = 0u16;
    if slow & SLOW_PATH_KBDFLAGS_RELEASE != 0 {
        out |= FASTPATH_INPUT_KBDFLAGS_RELEASE;
    }
    if slow & SLOW_PATH_KBDFLAGS_EXTENDED != 0 {
        out |= FASTPATH_INPUT_KBDFLAGS_EXTENDED;
    }
    if slow & SLOW_PATH_KBDFLAGS_EXTENDED1 != 0 {
        out |= FASTPATH_INPUT_KBDFLAGS_EXTENDED1;
    }
    out
}

/// Maximum number of `PersistentKeyList` PDUs accepted in one session
/// before the stage rejects further entries. Mirrors the DoS cap the
/// acceptor enforces during finalization.
const MAX_PERSISTENT_KEY_LIST_PDUS: u8 = 64;

/// Hard cap on per-channel SVC reassembly buffer size. Without this,
/// `ChannelPduHeader.length` (a wire-supplied `u32`) can drive a 4 GiB
/// `Vec::reserve` from a single FIRST chunk, OOM-killing the server
/// before any data byte arrives. 16 MiB is comfortably above the
/// largest message any of the standard SVC protocols (rdpsnd, cliprdr
/// in non-file mode, rdpdr) actually emits; channel handlers that need
/// to stream larger payloads (e.g. cliprdr file-transfer mode added in
/// §11.2c) can either chunk at the application layer or expose a
/// per-channel cap override on `RdpServerConfig`.
const MAX_SVC_REASSEMBLY_BYTES: u32 = 16 * 1024 * 1024;

/// First-byte sentinel that disambiguates the two top-level wire framings
/// the active session will receive:
///
/// - `0x03` -- TPKT version field (slow-path PDU follows).
/// - `0x00`-`0x03` action bits with the high two bits zero -- fast-path
///   input PDU (`FASTPATH_INPUT_ACTION_FASTPATH = 0x00` per
///   MS-RDPBCGR §2.2.8.1.2). The first-byte value `0x03` would also
///   match a fast-path action of `FASTPATH_INPUT_ACTION_X224` (defined
///   only for the legacy `X.224` fast-path mode that no real client
///   uses); we prefer the TPKT interpretation when in doubt because
///   real Windows clients never send `FASTPATH_INPUT_ACTION_X224`.
const TPKT_VERSION: u8 = 0x03;

/// Stream priority the server tags onto outbound `ShareDataHeader`.
/// `STREAM_LOW = 1` matches what acceptor finalization emits.
const STREAM_LOW: u8 = 1;

/// Outputs produced by [`ServerActiveStage::process`]. Each call may
/// produce zero or more outputs (a single client PDU can trigger both a
/// reply byte stream and a notification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveStageOutput {
    /// Wire bytes the caller MUST flush before reading the next client
    /// PDU. Already wrapped in TPKT + X.224 DT + MCS SDI + ShareControl
    /// + ShareData.
    SendBytes(Vec<u8>),
    /// Suppress Output PDU received from the client. `suppress = true`
    /// instructs the server to stop sending display updates; `false`
    /// resumes them, optionally bounded by `area`.
    SuppressOutput {
        suppress: bool,
        area: Option<DisplayRect>,
    },
    /// Refresh Rect PDU received -- the application SHOULD re-emit the
    /// listed regions.
    RefreshRect(Vec<DisplayRect>),
    /// Client requested an orderly shutdown via Shutdown Request PDU.
    /// The default policy (this commit) replies with `ShutdownDenied`
    /// and surfaces this notification so the application can decide
    /// whether to tear down the session voluntarily.
    ShutdownRequested,
    /// Client emitted a `ControlPdu(action = Detach)` post-finalization.
    /// The session is still alive but the client has released active
    /// control.
    ClientDetached,
    /// Complete (potentially multi-chunk reassembled) SVC payload from
    /// the client. The active stage performs the
    /// `CHANNEL_FLAG_FIRST` / `CHANNEL_FLAG_LAST` reassembly and emits
    /// the full message exactly once when the final chunk arrives.
    SvcData {
        /// MCS channel ID the data arrived on (matches one of the entries
        /// in `ServerActiveStage::channel_ids()`).
        channel_id: u16,
        /// Reassembled payload (post-`ChannelPduHeader`).
        payload: Vec<u8>,
    },
}

/// Per-channel reassembly state for inbound SVC data.
#[derive(Debug, Default)]
struct SvcReassembly {
    /// Total length declared in the FIRST chunk's `ChannelPduHeader.length`.
    expected_total: u32,
    /// Accumulated bytes; cleared when LAST is delivered or when a
    /// fresh FIRST arrives.
    buffer: Vec<u8>,
}

/// Server-side active session driver.
///
/// Construct via [`ServerActiveStage::new`] from the [`AcceptanceResult`]
/// produced by `RdpServer::take_acceptance_result`.
pub struct ServerActiveStage {
    config: RdpServerConfig,
    io_channel_id: u16,
    user_channel_id: u16,
    share_id: u32,
    /// Channel name → MCS channel ID, populated from the negotiation
    /// result. Used in Commit 9 to route SVC data to handlers.
    channel_ids: Vec<(alloc::string::String, u16)>,
    /// Mirrors the most recent client `Suppress Output` state.
    suppress_output: bool,
    /// PERSIST_BITMAP_KEYS PDUs received in the current session; capped
    /// to defend against a hostile client looping forever.
    persist_keys_count: u8,
    /// Per-channel inbound SVC reassembly state. Linear search is fine
    /// because the static-VC count is small (typically 1-3).
    svc_reassembly: Vec<(u16, SvcReassembly)>,
}

impl ServerActiveStage {
    /// Construct a new active stage from the acceptance result.
    pub fn new(result: AcceptanceResult, config: RdpServerConfig) -> Self {
        Self {
            config,
            io_channel_id: result.io_channel_id,
            user_channel_id: result.user_channel_id,
            share_id: result.share_id,
            channel_ids: result.channel_ids,
            suppress_output: false,
            persist_keys_count: 0,
            svc_reassembly: Vec::new(),
        }
    }

    /// Borrow the runtime config (chunk lengths, fragment sizes).
    pub fn config(&self) -> &RdpServerConfig {
        &self.config
    }

    /// MCS I/O channel ID the active session sends ShareControl PDUs on.
    pub fn io_channel_id(&self) -> u16 {
        self.io_channel_id
    }

    /// MCS user channel ID assigned to this client.
    pub fn user_channel_id(&self) -> u16 {
        self.user_channel_id
    }

    /// Negotiated share ID (echoed in every ShareDataHeader).
    pub fn share_id(&self) -> u32 {
        self.share_id
    }

    /// `true` while the client has asked the server to suppress display
    /// output (via Suppress Output PDU). Display encoders SHOULD honour
    /// this flag.
    pub fn is_output_suppressed(&self) -> bool {
        self.suppress_output
    }

    /// Number of PERSIST_BITMAP_KEYS PDUs accepted so far.
    pub fn persist_keys_count(&self) -> u8 {
        self.persist_keys_count
    }

    /// Channel name → MCS channel ID list for the active session.
    pub fn channel_ids(&self) -> &[(alloc::string::String, u16)] {
        &self.channel_ids
    }

    /// Process one complete client PDU.
    ///
    /// `input` MUST be a complete TPKT frame or a complete fast-path
    /// frame -- the caller is responsible for having framed the bytes
    /// using the same `PduHint` machinery the acceptor uses.
    ///
    /// `input_handler` is invoked for each decoded input event (slow-
    /// path or fast-path) before the function returns. Its callbacks
    /// are infallible (per the trait contract) so they never abort
    /// processing of a multi-event PDU mid-stream.
    pub fn process(
        &mut self,
        input: &[u8],
        input_handler: &mut dyn RdpServerInputHandler,
    ) -> ServerResult<Vec<ActiveStageOutput>> {
        if input.is_empty() {
            return Err(ServerError::protocol("empty active-stage PDU"));
        }
        match input[0] {
            TPKT_VERSION => self.process_slow_path(input, input_handler),
            // Fast-path action bits: 0x00 = FASTPATH_INPUT_ACTION_FASTPATH.
            // Anything else with the low two bits == 0 is also fast-path
            // (the upper 6 bits encode num_events / encryption flags).
            byte if (byte & 0x03) == 0x00 => self.process_fast_path_input(input, input_handler),
            _ => Err(ServerError::protocol("unrecognised PDU framing byte")),
        }
    }

    fn process_slow_path(
        &mut self,
        input: &[u8],
        input_handler: &mut dyn RdpServerInputHandler,
    ) -> ServerResult<Vec<ActiveStageOutput>> {
        let mut cursor = ReadCursor::new(input);
        let _tpkt = TpktHeader::decode(&mut cursor)?;
        let _dt = DataTransfer::decode(&mut cursor)?;
        let sdr = SendDataRequest::decode(&mut cursor)?;

        if sdr.initiator != self.user_channel_id {
            return Err(ServerError::protocol(
                "slow-path SDR initiator does not match assigned user channel",
            ));
        }

        if sdr.channel_id == self.io_channel_id {
            self.process_io_channel(sdr.user_data, input_handler)
        } else if self.channel_ids.iter().any(|(_, id)| *id == sdr.channel_id) {
            self.process_svc_inbound(sdr.channel_id, sdr.user_data)
        } else {
            Err(ServerError::protocol(
                "SDR channel ID is neither the I/O channel nor any negotiated VC",
            ))
        }
    }

    /// Decode one chunk of inbound SVC traffic. The active stage owns
    /// the per-channel reassembly buffer and emits a single
    /// [`ActiveStageOutput::SvcData`] when the LAST chunk arrives.
    fn process_svc_inbound(
        &mut self,
        channel_id: u16,
        user_data: &[u8],
    ) -> ServerResult<Vec<ActiveStageOutput>> {
        let mut cursor = ReadCursor::new(user_data);
        let header = ChannelPduHeader::decode(&mut cursor)?;
        if header.flags & CHANNEL_PACKET_COMPRESSED != 0 {
            return Err(ServerError::protocol(
                "compressed SVC chunk received but bulk decompression \
                 is not wired into the server skeleton",
            ));
        }
        let chunk = cursor.peek_remaining();
        let is_first = header.flags & CHANNEL_FLAG_FIRST != 0;
        let is_last = header.flags & CHANNEL_FLAG_LAST != 0;

        // Single-chunk fast path: FIRST and LAST set together. Skip the
        // per-channel buffer entirely and emit straight away.
        if is_first && is_last {
            // Drop any stale partial buffer the client left behind.
            self.svc_reassembly.retain(|(id, _)| *id != channel_id);
            if header.length > MAX_SVC_REASSEMBLY_BYTES {
                return Err(ServerError::protocol(
                    "single-chunk SVC PDU exceeds MAX_SVC_REASSEMBLY_BYTES",
                ));
            }
            let total_len = header.length as usize;
            if chunk.len() != total_len {
                return Err(ServerError::protocol(
                    "single-chunk SVC PDU body length disagrees with \
                     ChannelPduHeader.length",
                ));
            }
            return Ok(alloc::vec![ActiveStageOutput::SvcData {
                channel_id,
                payload: chunk.to_vec(),
            }]);
        }

        // Multi-chunk path: only create per-channel state once a valid
        // FIRST chunk arrives. A continuation arriving without an
        // existing entry is an error; we deliberately do *not* push a
        // default entry here so a hostile client cannot grow
        // `svc_reassembly` by spamming lone NEXT chunks across distinct
        // channel IDs.
        let entry_idx = self
            .svc_reassembly
            .iter()
            .position(|(id, _)| *id == channel_id);

        if is_first {
            // Cap the declared total before reserve() to prevent a
            // single FIRST chunk from triggering a 4 GiB allocation.
            if header.length > MAX_SVC_REASSEMBLY_BYTES {
                return Err(ServerError::protocol(
                    "SVC FIRST chunk total length exceeds MAX_SVC_REASSEMBLY_BYTES",
                ));
            }
            let entry = match entry_idx {
                Some(idx) => &mut self.svc_reassembly[idx].1,
                None => {
                    self.svc_reassembly.push((channel_id, SvcReassembly::default()));
                    &mut self.svc_reassembly.last_mut().unwrap().1
                }
            };
            entry.expected_total = header.length;
            entry.buffer.clear();
            entry.buffer.reserve(header.length as usize);
        } else {
            // Continuation chunk: entry MUST already exist (created by
            // a prior FIRST). If it does not, reject without allocating.
            let Some(idx) = entry_idx else {
                return Err(ServerError::protocol(
                    "SVC continuation chunk received without a preceding \
                     CHANNEL_FLAG_FIRST",
                ));
            };
            let entry = &self.svc_reassembly[idx].1;
            if entry.buffer.is_empty() {
                return Err(ServerError::protocol(
                    "SVC continuation chunk received without a preceding \
                     CHANNEL_FLAG_FIRST",
                ));
            }
            if header.length != entry.expected_total {
                return Err(ServerError::protocol(
                    "SVC continuation chunk reports a different total length \
                     than the FIRST chunk",
                ));
            }
        }

        // Re-borrow as &mut after the immutable validation borrow above.
        let entry = &mut self
            .svc_reassembly
            .iter_mut()
            .find(|(id, _)| *id == channel_id)
            .expect("entry was located or created above")
            .1;

        entry.buffer.extend_from_slice(chunk);
        if entry.buffer.len() > entry.expected_total as usize {
            return Err(ServerError::protocol(
                "SVC reassembled buffer exceeds the FIRST chunk's declared total",
            ));
        }

        if is_last {
            if entry.buffer.len() != entry.expected_total as usize {
                return Err(ServerError::protocol(
                    "SVC LAST chunk arrived with reassembled length \
                     different from the FIRST chunk's declared total",
                ));
            }
            let payload = core::mem::take(&mut entry.buffer);
            entry.expected_total = 0;
            return Ok(alloc::vec![ActiveStageOutput::SvcData {
                channel_id,
                payload,
            }]);
        }
        Ok(Vec::new())
    }

    /// Encode an outbound SVC payload as one or more wire-ready frames
    /// (TPKT + X.224 DT + MCS SDI + ChannelPduHeader + chunk).
    ///
    /// Splits `payload` into chunks of at most
    /// `config.channel_chunk_length` bytes per
    /// [`MAX_CHANNEL_CHUNK_LENGTH`] (MS-RDPBCGR §2.2.7.1.10). The
    /// `ChannelPduHeader.length` field carries the **total uncompressed
    /// message length** in every chunk; `flags` carries
    /// `CHANNEL_FLAG_FIRST` on the first chunk, `CHANNEL_FLAG_LAST` on
    /// the last, both on a single-chunk message.
    ///
    /// `channel_id` MUST be a negotiated SVC channel; otherwise the
    /// helper returns `ServerError::protocol(_)`.
    ///
    /// [`MAX_CHANNEL_CHUNK_LENGTH`]: crate::MAX_CHANNEL_CHUNK_LENGTH
    pub fn encode_svc_send(
        &self,
        channel_id: u16,
        payload: &[u8],
    ) -> ServerResult<Vec<Vec<u8>>> {
        if !self.channel_ids.iter().any(|(_, id)| *id == channel_id) {
            return Err(ServerError::protocol(
                "encode_svc_send target channel is not in the negotiated VC list",
            ));
        }
        let total = payload.len();
        if total > u32::MAX as usize {
            return Err(ServerError::protocol(
                "SVC payload exceeds u32 ChannelPduHeader.length",
            ));
        }
        let chunk_size = self.config.channel_chunk_length;

        if total == 0 {
            // Empty messages still need to declare presence with a
            // FIRST|LAST chunk carrying zero data bytes.
            return Ok(alloc::vec![self.frame_one_svc_chunk(
                channel_id,
                CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST,
                0,
                &[],
            )?]);
        }

        let mut frames = Vec::with_capacity(total.div_ceil(chunk_size));
        let mut offset = 0usize;
        while offset < total {
            let end = (offset + chunk_size).min(total);
            let mut flags = 0u32;
            if offset == 0 {
                flags |= CHANNEL_FLAG_FIRST;
            }
            if end == total {
                flags |= CHANNEL_FLAG_LAST;
            }
            frames.push(self.frame_one_svc_chunk(
                channel_id,
                flags,
                total as u32,
                &payload[offset..end],
            )?);
            offset = end;
        }
        Ok(frames)
    }

    /// Encode a clean-disconnect sequence: `SetErrorInfoPdu` (wrapped
    /// in ShareData on the I/O channel) followed by a top-level MCS
    /// `DisconnectProviderUltimatum` (TPKT + X.224 DT + 2-byte PER).
    ///
    /// Returns the two frames in order. The caller MUST flush both
    /// before closing the underlying transport so the client can
    /// surface a coherent disconnect reason rather than seeing only a
    /// half-open TCP close.
    ///
    /// The MCS reason is fixed at `UserRequested` (3) for the
    /// server-initiated path; the actual cause of the disconnect is
    /// carried by the preceding `SetErrorInfoPdu`'s
    /// [`ErrorInfoCode`].
    pub fn encode_disconnect(&self, code: ErrorInfoCode) -> ServerResult<Vec<Vec<u8>>> {
        let info = SetErrorInfoPdu::new(code);
        let info_frame = self.encode_share_data(ShareDataPduType::SetErrorInfo, &info)?;
        let ult_frame = self.encode_disconnect_ultimatum(DisconnectReason::UserRequested)?;
        Ok(alloc::vec![info_frame, ult_frame])
    }

    /// Encode a stand-alone `DisconnectProviderUltimatum` frame
    /// (TPKT + X.224 DT + 2-byte PER body). Use this when no
    /// `SetErrorInfoPdu` is needed (e.g. fatal protocol error mid-handshake).
    pub fn encode_disconnect_ultimatum(
        &self,
        reason: DisconnectReason,
    ) -> ServerResult<Vec<u8>> {
        let ult = DisconnectProviderUltimatum { reason };
        let payload_size = DATA_TRANSFER_HEADER_SIZE + ult.size();
        let total = TPKT_HEADER_SIZE + payload_size;
        let mut buf = vec![0u8; total];
        {
            let mut c = WriteCursor::new(&mut buf);
            TpktHeader::try_for_payload(payload_size)?.encode(&mut c)?;
            DataTransfer.encode(&mut c)?;
            ult.encode(&mut c)?;
        }
        Ok(buf)
    }

    fn frame_one_svc_chunk(
        &self,
        channel_id: u16,
        flags: u32,
        total_length: u32,
        chunk: &[u8],
    ) -> ServerResult<Vec<u8>> {
        let header = ChannelPduHeader {
            length: total_length,
            flags,
        };
        let body_size = CHANNEL_PDU_HEADER_SIZE + chunk.len();
        let mut body = vec![0u8; body_size];
        {
            let mut c = WriteCursor::new(&mut body);
            header.encode(&mut c)?;
            c.write_slice(chunk, "svc::chunkData")?;
        }
        let sdi = SendDataIndication {
            initiator: self.user_channel_id,
            channel_id,
            user_data: &body,
        };
        let payload_size = DATA_TRANSFER_HEADER_SIZE + sdi.size();
        let total = TPKT_HEADER_SIZE + payload_size;
        let mut buf = vec![0u8; total];
        {
            let mut c = WriteCursor::new(&mut buf);
            TpktHeader::try_for_payload(payload_size)?.encode(&mut c)?;
            DataTransfer.encode(&mut c)?;
            sdi.encode(&mut c)?;
        }
        Ok(buf)
    }

    fn process_io_channel(
        &mut self,
        user_data: &[u8],
        input_handler: &mut dyn RdpServerInputHandler,
    ) -> ServerResult<Vec<ActiveStageOutput>> {
        let mut cursor = ReadCursor::new(user_data);
        let sc_hdr = ShareControlHeader::decode(&mut cursor)?;
        if sc_hdr.pdu_type != ShareControlPduType::Data {
            return Err(ServerError::protocol(
                "active-session ShareControl PDU is not a Data PDU",
            ));
        }
        let sd_hdr = ShareDataHeader::decode(&mut cursor)?;
        if sd_hdr.share_id != self.share_id {
            return Err(ServerError::protocol(
                "ShareData.shareId does not match the negotiated value",
            ));
        }
        let body = cursor.peek_remaining();
        self.dispatch_share_data(sd_hdr.pdu_type2, body, input_handler)
    }

    fn dispatch_share_data(
        &mut self,
        pdu_type2: ShareDataPduType,
        body: &[u8],
        input_handler: &mut dyn RdpServerInputHandler,
    ) -> ServerResult<Vec<ActiveStageOutput>> {
        match pdu_type2 {
            ShareDataPduType::RefreshRect => self.handle_refresh_rect(body),
            ShareDataPduType::SuppressOutput => self.handle_suppress_output(body),
            ShareDataPduType::ShutdownRequest => self.handle_shutdown_request(body),
            ShareDataPduType::Control => self.handle_control(body),
            ShareDataPduType::PersistentKeyList => self.handle_persistent_key_list(body),
            ShareDataPduType::Input => self.handle_slow_path_input(body, input_handler),
            other => Err(ServerError::protocol_owned(alloc::format!(
                "unexpected ShareData PDU type in active session: {other:?}"
            ))),
        }
    }

    /// Decode a slow-path `TS_INPUT_PDU` (MS-RDPBCGR §2.2.8.1.1.3) and
    /// dispatch each `TS_INPUT_EVENT` to the input handler. Real
    /// Windows clients almost never use this path -- they prefer
    /// fast-path -- but the spec permits it and the loopback test in
    /// Commit 10 exercises it.
    fn handle_slow_path_input(
        &mut self,
        body: &[u8],
        input_handler: &mut dyn RdpServerInputHandler,
    ) -> ServerResult<Vec<ActiveStageOutput>> {
        let pdu = InputEventPdu::decode(&mut ReadCursor::new(body))?;
        let expected_data_len = usize::from(pdu.num_events) * SLOW_PATH_INPUT_EVENT_SIZE;
        if pdu.event_data.len() < expected_data_len {
            return Err(ServerError::protocol(
                "slow-path InputEventPdu.event_data shorter than num_events * 12 bytes",
            ));
        }
        for event_idx in 0..pdu.num_events as usize {
            let off = event_idx * SLOW_PATH_INPUT_EVENT_SIZE;
            let chunk = &pdu.event_data[off..off + SLOW_PATH_INPUT_EVENT_SIZE];
            let mut c = ReadCursor::new(chunk);
            let _event_time = c.read_u32_le("TS_INPUT_EVENT::eventTime")?;
            let raw_msg = c.read_u16_le("TS_INPUT_EVENT::messageType")?;
            // Skip events with unrecognised messageType rather than
            // erroring -- a forward-compatible client may emit a type
            // we have not learned yet.
            let Ok(msg) = decode_slow_path_message_type(raw_msg) else {
                continue;
            };
            match msg {
                InputEventType::Synchronize => {
                    // toggleFlags is a u32 LE in the slow-path layout
                    // but only the low byte carries meaningful state.
                    let toggle = c.read_u32_le("TS_SYNCHRONIZE_EVENT::toggleFlags")?;
                    input_handler.on_sync(toggle as u8);
                }
                InputEventType::ScanCode => {
                    let kbd_flags = c.read_u16_le("TS_KEYBOARD_EVENT::keyboardFlags")?;
                    let key_code = c.read_u16_le("TS_KEYBOARD_EVENT::keyCode")?;
                    let _pad = c.read_u16_le("TS_KEYBOARD_EVENT::pad")?;
                    let translated = slow_path_kbd_flags_to_fast_path(kbd_flags);
                    input_handler.on_keyboard_scancode(translated, key_code as u8);
                }
                InputEventType::Unicode => {
                    let kbd_flags = c.read_u16_le("TS_UNICODE_KEYBOARD_EVENT::keyboardFlags")?;
                    let unicode = c.read_u16_le("TS_UNICODE_KEYBOARD_EVENT::unicodeCode")?;
                    let _pad = c.read_u16_le("TS_UNICODE_KEYBOARD_EVENT::pad")?;
                    let translated = slow_path_kbd_flags_to_fast_path(kbd_flags);
                    input_handler.on_keyboard_unicode(translated, unicode);
                }
                InputEventType::Mouse => {
                    let pf = c.read_u16_le("TS_POINTER_EVENT::pointerFlags")?;
                    let x = c.read_u16_le("TS_POINTER_EVENT::xPos")?;
                    let y = c.read_u16_le("TS_POINTER_EVENT::yPos")?;
                    input_handler.on_mouse(pf, x, y);
                }
                InputEventType::ExtendedMouse => {
                    let pf = c.read_u16_le("TS_POINTERX_EVENT::pointerFlags")?;
                    let x = c.read_u16_le("TS_POINTERX_EVENT::xPos")?;
                    let y = c.read_u16_le("TS_POINTERX_EVENT::yPos")?;
                    input_handler.on_mouse_extended(pf, x, y);
                }
            }
        }
        Ok(Vec::new())
    }

    /// Decode a fast-path input PDU (MS-RDPBCGR §2.2.8.1.2) and
    /// dispatch each `FastPathInputEvent` to the input handler.
    ///
    /// The wire form has `num_events` (from the header) events
    /// concatenated immediately after the length field; iteration
    /// continues until either `num_events` events have been decoded or
    /// the cursor is exhausted, whichever happens first.
    fn process_fast_path_input(
        &mut self,
        input: &[u8],
        input_handler: &mut dyn RdpServerInputHandler,
    ) -> ServerResult<Vec<ActiveStageOutput>> {
        let mut cursor = ReadCursor::new(input);
        let header = FastPathInputHeader::decode(&mut cursor)?;
        // The PDU may carry encryption flags we cannot honour without
        // negotiated keys; fail loud rather than silently misinterpret.
        if header.flags != 0 {
            return Err(ServerError::protocol(
                "encrypted fast-path input PDU received but no security context is active",
            ));
        }
        let mut decoded = 0u8;
        while decoded < header.num_events && cursor.remaining() > 0 {
            let event = FastPathInputEvent::decode(&mut cursor)?;
            self.dispatch_fast_path_event(event, input_handler);
            decoded += 1;
        }
        Ok(Vec::new())
    }

    fn dispatch_fast_path_event(
        &self,
        event: FastPathInputEvent,
        input_handler: &mut dyn RdpServerInputHandler,
    ) {
        match event {
            FastPathInputEvent::Scancode(e) => {
                input_handler.on_keyboard_scancode(u16::from(e.event_flags), e.key_code);
            }
            FastPathInputEvent::Unicode(e) => {
                input_handler.on_keyboard_unicode(u16::from(e.event_flags), e.unicode_code);
            }
            FastPathInputEvent::Mouse(e) => {
                input_handler.on_mouse(e.pointer_flags, e.x_pos, e.y_pos);
            }
            FastPathInputEvent::MouseX(e) => {
                input_handler.on_mouse_extended(e.pointer_flags, e.x_pos, e.y_pos);
            }
            FastPathInputEvent::RelativeMouse(e) => {
                input_handler.on_mouse_relative(u16::from(e.event_flags), e.x_delta, e.y_delta);
            }
            FastPathInputEvent::Sync(e) => {
                input_handler.on_sync(e.event_flags);
            }
            FastPathInputEvent::QoeTimestamp(e) => {
                input_handler.on_qoe_timestamp(e.timestamp);
            }
        }
    }

    fn handle_refresh_rect(&mut self, body: &[u8]) -> ServerResult<Vec<ActiveStageOutput>> {
        let pdu = RefreshRectPdu::decode(&mut ReadCursor::new(body))?;
        let areas: Vec<DisplayRect> = pdu
            .areas
            .into_iter()
            .map(|a| DisplayRect {
                left: a.left,
                top: a.top,
                right: a.right,
                bottom: a.bottom,
            })
            .collect();
        Ok(vec![ActiveStageOutput::RefreshRect(areas)])
    }

    fn handle_suppress_output(&mut self, body: &[u8]) -> ServerResult<Vec<ActiveStageOutput>> {
        let pdu = SuppressOutputPdu::decode(&mut ReadCursor::new(body))?;
        let suppress = pdu.allow_display_updates == 0;
        self.suppress_output = suppress;
        let area = match (pdu.left, pdu.top, pdu.right, pdu.bottom) {
            (Some(l), Some(t), Some(r), Some(b)) => Some(DisplayRect {
                left: l,
                top: t,
                right: r,
                bottom: b,
            }),
            _ => None,
        };
        Ok(vec![ActiveStageOutput::SuppressOutput { suppress, area }])
    }

    fn handle_shutdown_request(&mut self, body: &[u8]) -> ServerResult<Vec<ActiveStageOutput>> {
        // Body MUST be empty per MS-RDPBCGR §2.2.2.2 -- decode validates.
        let _ = ShutdownRequestPdu::decode(&mut ReadCursor::new(body))?;
        // Default policy: emit a ShutdownDenied response immediately so
        // the client knows the server saw the request, and surface the
        // notification so the caller can decide to actually disconnect.
        let denied = self.encode_share_data(
            ShareDataPduType::ShutdownDenied,
            &ShutdownDeniedPdu,
        )?;
        Ok(vec![
            ActiveStageOutput::SendBytes(denied),
            ActiveStageOutput::ShutdownRequested,
        ])
    }

    fn handle_control(&mut self, body: &[u8]) -> ServerResult<Vec<ActiveStageOutput>> {
        let pdu = ControlPdu::decode(&mut ReadCursor::new(body))?;
        match pdu.action {
            ControlAction::RequestControl => {
                // FreeRDP-style: grant control. MS-RDPBCGR §2.2.1.16
                // does not formally cover RequestControl in the active
                // phase, but mstsc tolerates an immediate
                // GrantedControl with grantId=user_channel_id and
                // controlId=user_channel_id.
                let granted = ControlPdu {
                    action: ControlAction::GrantedControl,
                    grant_id: self.user_channel_id,
                    control_id: self.user_channel_id as u32,
                };
                let bytes = self.encode_share_data(ShareDataPduType::Control, &granted)?;
                Ok(vec![ActiveStageOutput::SendBytes(bytes)])
            }
            ControlAction::Detach => Ok(vec![ActiveStageOutput::ClientDetached]),
            // Cooperate / GrantedControl are server→client only -- a
            // client that emits them is malformed.
            other => Err(ServerError::protocol_owned(alloc::format!(
                "client sent unsupported ControlPdu action: {other:?}"
            ))),
        }
    }

    fn handle_persistent_key_list(&mut self, body: &[u8]) -> ServerResult<Vec<ActiveStageOutput>> {
        if self.persist_keys_count >= MAX_PERSISTENT_KEY_LIST_PDUS {
            return Err(ServerError::protocol(
                "exceeded MAX_PERSISTENT_KEY_LIST_PDUS in active session",
            ));
        }
        // Validate the PDU is well-formed; we do not inspect the cache
        // contents in this skeleton.
        let _ = PersistentKeyListPdu::decode(&mut ReadCursor::new(body))?;
        self.persist_keys_count += 1;
        Ok(Vec::new())
    }

    /// Wrap an inner ShareData body in ShareData + ShareControl + MCS
    /// SDI + X.224 DT + TPKT and return the wire bytes.
    pub(crate) fn encode_share_data<E: Encode>(
        &self,
        pdu_type2: ShareDataPduType,
        inner: &E,
    ) -> ServerResult<Vec<u8>> {
        let inner_size = inner.size();
        if inner_size > u16::MAX as usize {
            return Err(ServerError::protocol(
                "ShareData inner body exceeds u16 uncompressedLength",
            ));
        }
        let sd_total = SHARE_DATA_HEADER_SIZE + inner_size;
        let sc_total = SHARE_CONTROL_HEADER_SIZE + sd_total;
        if sc_total > u16::MAX as usize {
            return Err(ServerError::protocol(
                "ShareControl payload exceeds u16 totalLength",
            ));
        }

        let mut sc_payload = vec![0u8; sc_total];
        {
            let mut cursor = WriteCursor::new(&mut sc_payload);
            ShareControlHeader {
                total_length: sc_total as u16,
                pdu_type: ShareControlPduType::Data,
                pdu_source: self.user_channel_id,
            }
            .encode(&mut cursor)?;
            ShareDataHeader {
                share_id: self.share_id,
                stream_id: STREAM_LOW,
                // MS-RDPBCGR §2.2.8.1.1.1.2: uncompressedLength excludes
                // the ShareDataHeader itself -- matches the acceptor's
                // finalization-side convention.
                uncompressed_length: inner_size as u16,
                pdu_type2,
                compressed_type: 0,
                compressed_length: 0,
            }
            .encode(&mut cursor)?;
            inner.encode(&mut cursor)?;
        }

        let sdi = SendDataIndication {
            initiator: self.user_channel_id,
            channel_id: self.io_channel_id,
            user_data: &sc_payload,
        };
        let payload_size = DATA_TRANSFER_HEADER_SIZE + sdi.size();
        let total = TPKT_HEADER_SIZE + payload_size;
        let mut buf = vec![0u8; total];
        {
            let mut cursor = WriteCursor::new(&mut buf);
            TpktHeader::try_for_payload(payload_size)?.encode(&mut cursor)?;
            DataTransfer.encode(&mut cursor)?;
            sdi.encode(&mut cursor)?;
        }
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use core::cell::RefCell;
    use justrdp_acceptor::AcceptanceResult;
    use justrdp_core::EncodeResult;
    use justrdp_pdu::rdp::fast_path::{
        FastPathInputHeader, FastPathMouseEvent, FastPathScancodeEvent, FastPathSyncEvent,
        FastPathUnicodeEvent, FASTPATH_INPUT_ACTION_FASTPATH,
    };
    use justrdp_pdu::rdp::finalization::InclusiveRect;
    use justrdp_pdu::x224::{NegotiationRequestFlags, NegotiationResponseFlags, SecurityProtocol};

    /// Minimal handler that drops every callback. Used by the
    /// control-PDU dispatch tests that don't care about input events.
    struct NoopHandler;
    impl RdpServerInputHandler for NoopHandler {}

    /// Recording handler -- captures every callback so the input
    /// dispatch tests can assert on the exact sequence of events.
    #[derive(Default)]
    struct RecordingHandler {
        events: RefCell<Vec<RecordedInput>>,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum RecordedInput {
        Scancode(u16, u8),
        Unicode(u16, u16),
        Mouse(u16, u16, u16),
        MouseX(u16, u16, u16),
        MouseRel(u16, i16, i16),
        Sync(u8),
        Qoe(u32),
    }

    impl RdpServerInputHandler for RecordingHandler {
        fn on_keyboard_scancode(&mut self, flags: u16, key_code: u8) {
            self.events.borrow_mut().push(RecordedInput::Scancode(flags, key_code));
        }
        fn on_keyboard_unicode(&mut self, flags: u16, unicode: u16) {
            self.events.borrow_mut().push(RecordedInput::Unicode(flags, unicode));
        }
        fn on_mouse(&mut self, pf: u16, x: u16, y: u16) {
            self.events.borrow_mut().push(RecordedInput::Mouse(pf, x, y));
        }
        fn on_mouse_extended(&mut self, pf: u16, x: u16, y: u16) {
            self.events.borrow_mut().push(RecordedInput::MouseX(pf, x, y));
        }
        fn on_mouse_relative(&mut self, pf: u16, dx: i16, dy: i16) {
            self.events.borrow_mut().push(RecordedInput::MouseRel(pf, dx, dy));
        }
        fn on_sync(&mut self, flags: u8) {
            self.events.borrow_mut().push(RecordedInput::Sync(flags));
        }
        fn on_qoe_timestamp(&mut self, ts: u32) {
            self.events.borrow_mut().push(RecordedInput::Qoe(ts));
        }
    }

    /// Build a minimally-populated AcceptanceResult so the active stage
    /// can be exercised without running the full handshake. All
    /// `ClientRequestInfo` / `AcceptanceResult` fields are `pub`, so a
    /// struct-literal is enough.
    fn fake_result() -> AcceptanceResult {
        AcceptanceResult {
            selected_protocol: SecurityProtocol::SSL,
            server_nego_flags: NegotiationResponseFlags::NONE,
            client_request: justrdp_acceptor::ClientRequestInfo {
                cookie: None,
                routing_token: None,
                requested_protocols: SecurityProtocol::SSL,
                request_flags: NegotiationRequestFlags::NONE,
                had_negotiation_request: true,
            },
            io_channel_id: 0x03EB,
            user_channel_id: 0x03EF,
            message_channel_id: None,
            share_id: 0x0001_03EA,
            channel_ids: alloc::vec![("rdpsnd".to_string(), 0x03EC)],
            client_capabilities: alloc::vec::Vec::new(),
            client_info: None,
        }
    }

    fn fake_stage() -> ServerActiveStage {
        let cfg = RdpServerConfig::builder().build().unwrap();
        ServerActiveStage::new(fake_result(), cfg)
    }

    /// Wrap an inner ShareData body in the same envelope a real client
    /// would (ShareData + ShareControl + SDR + DT + TPKT) so the
    /// process() entry can decode it.
    fn wrap_client_share_data<E: Encode>(
        stage: &ServerActiveStage,
        pdu_type2: ShareDataPduType,
        inner: &E,
    ) -> Vec<u8> {
        let inner_size = inner.size();
        let sd_total = SHARE_DATA_HEADER_SIZE + inner_size;
        let sc_total = SHARE_CONTROL_HEADER_SIZE + sd_total;
        let mut sc_payload = vec![0u8; sc_total];
        {
            let mut c = WriteCursor::new(&mut sc_payload);
            ShareControlHeader {
                total_length: sc_total as u16,
                pdu_type: ShareControlPduType::Data,
                pdu_source: stage.user_channel_id,
            }
            .encode(&mut c)
            .unwrap();
            ShareDataHeader {
                share_id: stage.share_id,
                stream_id: STREAM_LOW,
                uncompressed_length: inner_size as u16,
                pdu_type2,
                compressed_type: 0,
                compressed_length: 0,
            }
            .encode(&mut c)
            .unwrap();
            inner.encode(&mut c).unwrap();
        }
        let sdr = SendDataRequest {
            initiator: stage.user_channel_id,
            channel_id: stage.io_channel_id,
            user_data: &sc_payload,
        };
        let payload_size = DATA_TRANSFER_HEADER_SIZE + sdr.size();
        let total = TPKT_HEADER_SIZE + payload_size;
        let mut buf = vec![0u8; total];
        {
            let mut c = WriteCursor::new(&mut buf);
            TpktHeader::try_for_payload(payload_size).unwrap().encode(&mut c).unwrap();
            DataTransfer.encode(&mut c).unwrap();
            sdr.encode(&mut c).unwrap();
        }
        buf
    }

    #[test]
    fn empty_input_errors() {
        let mut s = fake_stage();
        assert!(s.process(&[], &mut NoopHandler).is_err());
    }

    #[test]
    fn unrecognised_first_byte_errors() {
        let mut s = fake_stage();
        // 0x05 -> low bits 0b01, neither TPKT (0x03) nor fast-path (0x00)
        let err = s.process(&[0x05, 0x00, 0x00, 0x00], &mut NoopHandler).unwrap_err();
        let msg = alloc::format!("{err}");
        assert!(msg.contains("framing"), "got: {msg}");
    }

    /// Build a fast-path input PDU carrying the supplied events. Used
    /// by the input-dispatch tests below.
    fn build_fast_path_input(events: Vec<FastPathInputEvent>) -> Vec<u8> {
        let body_size: usize = events.iter().map(|e| e.size()).sum();
        let provisional_total = 1 + 2 + body_size; // assume long-form length
        let total = if provisional_total <= 0x7F { 2 + body_size } else { provisional_total };
        let header = FastPathInputHeader {
            action: FASTPATH_INPUT_ACTION_FASTPATH,
            num_events: events.len() as u8,
            flags: 0,
            length: total as u16,
        };
        let mut buf = vec![0u8; header.size() + body_size];
        let mut c = WriteCursor::new(&mut buf);
        header.encode(&mut c).unwrap();
        for e in events {
            e.encode(&mut c).unwrap();
        }
        buf
    }

    #[test]
    fn fast_path_scancode_dispatches_to_handler() {
        let mut s = fake_stage();
        let mut h = RecordingHandler::default();
        let pdu = build_fast_path_input(vec![FastPathInputEvent::Scancode(
            FastPathScancodeEvent { event_flags: 0x01, key_code: 0x1E },
        )]);
        s.process(&pdu, &mut h).unwrap();
        assert_eq!(
            h.events.into_inner(),
            vec![RecordedInput::Scancode(0x01, 0x1E)]
        );
    }

    #[test]
    fn fast_path_multi_event_pdu_dispatches_each_event() {
        let mut s = fake_stage();
        let mut h = RecordingHandler::default();
        let pdu = build_fast_path_input(vec![
            FastPathInputEvent::Mouse(FastPathMouseEvent {
                event_flags: 0,
                pointer_flags: 0x8000,
                x_pos: 100,
                y_pos: 200,
            }),
            FastPathInputEvent::Sync(FastPathSyncEvent { event_flags: 0x07 }),
            FastPathInputEvent::Unicode(FastPathUnicodeEvent {
                event_flags: 0,
                unicode_code: 0x0041,
            }),
        ]);
        s.process(&pdu, &mut h).unwrap();
        assert_eq!(
            h.events.into_inner(),
            vec![
                RecordedInput::Mouse(0x8000, 100, 200),
                RecordedInput::Sync(0x07),
                RecordedInput::Unicode(0, 0x0041),
            ]
        );
    }

    #[test]
    fn refresh_rect_emits_notification() {
        let mut s = fake_stage();
        let pdu = RefreshRectPdu {
            areas: alloc::vec![
                InclusiveRect { left: 0, top: 0, right: 99, bottom: 99 },
                InclusiveRect { left: 100, top: 100, right: 199, bottom: 199 },
            ],
        };
        let bytes = wrap_client_share_data(&s, ShareDataPduType::RefreshRect, &pdu);
        let out = s.process(&bytes, &mut NoopHandler).unwrap();
        match out.as_slice() {
            [ActiveStageOutput::RefreshRect(areas)] => {
                assert_eq!(areas.len(), 2);
                assert_eq!(
                    areas[0],
                    DisplayRect { left: 0, top: 0, right: 99, bottom: 99 }
                );
                assert_eq!(
                    areas[1],
                    DisplayRect { left: 100, top: 100, right: 199, bottom: 199 }
                );
            }
            other => panic!("expected RefreshRect, got: {other:?}"),
        }
    }

    #[test]
    fn suppress_output_suppress_with_no_area() {
        let mut s = fake_stage();
        let pdu = SuppressOutputPdu {
            allow_display_updates: 0,
            left: None,
            top: None,
            right: None,
            bottom: None,
        };
        let bytes = wrap_client_share_data(&s, ShareDataPduType::SuppressOutput, &pdu);
        let out = s.process(&bytes, &mut NoopHandler).unwrap();
        match out.as_slice() {
            [ActiveStageOutput::SuppressOutput { suppress: true, area: None }] => {}
            other => panic!("expected SuppressOutput(true,None), got: {other:?}"),
        }
        assert!(s.is_output_suppressed());
    }

    #[test]
    fn suppress_output_resume_with_area() {
        let mut s = fake_stage();
        // Mark suppressed first to confirm the resume flips it back.
        s.suppress_output = true;
        let pdu = SuppressOutputPdu {
            allow_display_updates: 1,
            left: Some(0),
            top: Some(0),
            right: Some(799),
            bottom: Some(599),
        };
        let bytes = wrap_client_share_data(&s, ShareDataPduType::SuppressOutput, &pdu);
        let out = s.process(&bytes, &mut NoopHandler).unwrap();
        match out.as_slice() {
            [ActiveStageOutput::SuppressOutput {
                suppress: false,
                area: Some(DisplayRect { left: 0, top: 0, right: 799, bottom: 599 }),
            }] => {}
            other => panic!("expected resume with area, got: {other:?}"),
        }
        assert!(!s.is_output_suppressed());
    }

    #[test]
    fn shutdown_request_replies_denied_and_notifies() {
        let mut s = fake_stage();
        let bytes = wrap_client_share_data(&s, ShareDataPduType::ShutdownRequest, &ShutdownRequestPdu);
        let out = s.process(&bytes, &mut NoopHandler).unwrap();
        assert_eq!(out.len(), 2);
        match &out[0] {
            ActiveStageOutput::SendBytes(b) => {
                // Decode the reply and verify pduType2 == ShutdownDenied.
                let mut c = ReadCursor::new(b);
                let _tpkt = TpktHeader::decode(&mut c).unwrap();
                let _dt = DataTransfer::decode(&mut c).unwrap();
                let sdi = SendDataIndication::decode(&mut c).unwrap();
                let mut inner = ReadCursor::new(sdi.user_data);
                let sc = ShareControlHeader::decode(&mut inner).unwrap();
                assert_eq!(sc.pdu_type, ShareControlPduType::Data);
                let sd = ShareDataHeader::decode(&mut inner).unwrap();
                assert_eq!(sd.pdu_type2, ShareDataPduType::ShutdownDenied);
                assert_eq!(sd.share_id, s.share_id);
            }
            other => panic!("expected SendBytes, got: {other:?}"),
        }
        assert!(matches!(out[1], ActiveStageOutput::ShutdownRequested));
    }

    #[test]
    fn control_request_emits_granted_control_reply() {
        let mut s = fake_stage();
        let req = ControlPdu {
            action: ControlAction::RequestControl,
            grant_id: 0,
            control_id: 0,
        };
        let bytes = wrap_client_share_data(&s, ShareDataPduType::Control, &req);
        let out = s.process(&bytes, &mut NoopHandler).unwrap();
        assert_eq!(out.len(), 1);
        match &out[0] {
            ActiveStageOutput::SendBytes(b) => {
                let mut c = ReadCursor::new(b);
                let _tpkt = TpktHeader::decode(&mut c).unwrap();
                let _dt = DataTransfer::decode(&mut c).unwrap();
                let sdi = SendDataIndication::decode(&mut c).unwrap();
                let mut inner = ReadCursor::new(sdi.user_data);
                let _sc = ShareControlHeader::decode(&mut inner).unwrap();
                let sd = ShareDataHeader::decode(&mut inner).unwrap();
                assert_eq!(sd.pdu_type2, ShareDataPduType::Control);
                let body = inner.peek_remaining();
                let granted = ControlPdu::decode(&mut ReadCursor::new(body)).unwrap();
                assert_eq!(granted.action, ControlAction::GrantedControl);
                assert_eq!(granted.grant_id, s.user_channel_id);
                assert_eq!(granted.control_id, s.user_channel_id as u32);
            }
            other => panic!("expected SendBytes, got: {other:?}"),
        }
    }

    #[test]
    fn control_detach_emits_client_detached() {
        let mut s = fake_stage();
        let req = ControlPdu {
            action: ControlAction::Detach,
            grant_id: 0,
            control_id: 0,
        };
        let bytes = wrap_client_share_data(&s, ShareDataPduType::Control, &req);
        let out = s.process(&bytes, &mut NoopHandler).unwrap();
        assert!(matches!(out.as_slice(), [ActiveStageOutput::ClientDetached]));
    }

    #[test]
    fn control_unsupported_action_errors() {
        let mut s = fake_stage();
        let req = ControlPdu {
            action: ControlAction::Cooperate,
            grant_id: 0,
            control_id: 0,
        };
        let bytes = wrap_client_share_data(&s, ShareDataPduType::Control, &req);
        assert!(s.process(&bytes, &mut NoopHandler).is_err());
    }

    #[test]
    fn persistent_key_list_consumed_silently_within_cap() {
        let mut s = fake_stage();
        // Empty PersistentKeyListPdu is well-formed (zero entries).
        let pdu = PersistentKeyListPdu {
            num_entries: [0; 5],
            total_entries: [0; 5],
            flags: 0x03, // PERSIST_FIRST_PDU | PERSIST_LAST_PDU
            keys: alloc::vec::Vec::new(),
        };
        let bytes = wrap_client_share_data(&s, ShareDataPduType::PersistentKeyList, &pdu);
        let out = s.process(&bytes, &mut NoopHandler).unwrap();
        assert!(out.is_empty());
        assert_eq!(s.persist_keys_count(), 1);
    }

    #[test]
    fn persistent_key_list_dos_cap_enforced() {
        let mut s = fake_stage();
        s.persist_keys_count = MAX_PERSISTENT_KEY_LIST_PDUS;
        let pdu = PersistentKeyListPdu {
            num_entries: [0; 5],
            total_entries: [0; 5],
            flags: 0x03,
            keys: alloc::vec::Vec::new(),
        };
        let bytes = wrap_client_share_data(&s, ShareDataPduType::PersistentKeyList, &pdu);
        assert!(s.process(&bytes, &mut NoopHandler).is_err());
    }

    #[test]
    fn slow_path_input_scancode_dispatches_to_handler() {
        let mut s = fake_stage();
        let mut h = RecordingHandler::default();
        // Build TS_INPUT_PDU with one TS_KEYBOARD_EVENT (12 bytes total)
        // KBDFLAGS_RELEASE = 0x8000 -> fast-path 0x01 after translation.
        let mut event_data = vec![0u8; SLOW_PATH_INPUT_EVENT_SIZE];
        let mut c = WriteCursor::new(&mut event_data);
        c.write_u32_le(0x1234_5678, "eventTime").unwrap();
        c.write_u16_le(0x0004, "messageType: ScanCode").unwrap();
        c.write_u16_le(0x8000, "keyboardFlags: KBDFLAGS_RELEASE").unwrap();
        c.write_u16_le(0x001E, "keyCode").unwrap();
        c.write_u16_le(0x0000, "pad").unwrap();
        let pdu = InputEventPdu {
            num_events: 1,
            event_data,
        };
        let bytes = wrap_client_share_data(&s, ShareDataPduType::Input, &pdu);
        s.process(&bytes, &mut h).unwrap();
        // Slow-path KBDFLAGS_RELEASE (0x8000) must translate to
        // fast-path FASTPATH_INPUT_KBDFLAGS_RELEASE (0x01).
        assert_eq!(
            h.events.into_inner(),
            vec![RecordedInput::Scancode(0x01, 0x1E)]
        );
    }

    #[test]
    fn slow_path_input_unknown_message_type_skipped() {
        let mut s = fake_stage();
        let mut h = RecordingHandler::default();
        // Two events: one valid mouse, one with unrecognised messageType.
        let mut event_data = vec![0u8; SLOW_PATH_INPUT_EVENT_SIZE * 2];
        {
            let mut c = WriteCursor::new(&mut event_data);
            // Event 1: unknown messageType 0xCAFE.
            c.write_u32_le(0, "eventTime").unwrap();
            c.write_u16_le(0xCAFE, "messageType: unknown").unwrap();
            c.write_slice(&[0u8; 6], "padding").unwrap();
            // Event 2: valid mouse.
            c.write_u32_le(0, "eventTime").unwrap();
            c.write_u16_le(0x8001, "messageType: Mouse").unwrap();
            c.write_u16_le(0x0800, "pointerFlags: MOVE").unwrap();
            c.write_u16_le(50, "xPos").unwrap();
            c.write_u16_le(60, "yPos").unwrap();
        }
        let pdu = InputEventPdu {
            num_events: 2,
            event_data,
        };
        let bytes = wrap_client_share_data(&s, ShareDataPduType::Input, &pdu);
        s.process(&bytes, &mut h).unwrap();
        // Only the second (valid) event reaches the handler.
        assert_eq!(
            h.events.into_inner(),
            vec![RecordedInput::Mouse(0x0800, 50, 60)]
        );
    }

    #[test]
    fn fast_path_encrypted_pdu_rejected() {
        // flags != 0 means the PDU expects a security context we don't
        // have; the active stage MUST refuse rather than silently
        // misinterpret the body.
        let mut s = fake_stage();
        let mut h = NoopHandler;
        // FASTPATH_INPUT_ENCRYPTED is at bit 6 (value 0x40 in the byte
        // when packed via (flags << 6)). Build the byte directly.
        let header_byte = 0x00 | (0x01 << 6); // action=0, flags=ENCRYPTED
        let bytes = [header_byte, 0x02];
        assert!(s.process(&bytes, &mut h).is_err());
    }

    #[test]
    fn unrecognised_share_data_type_errors() {
        let mut s = fake_stage();
        // PlaySound (34 = 0x22) is server→client only; client emitting it
        // is malformed.
        let bytes = wrap_client_share_data(&s, ShareDataPduType::PlaySound, &EmptyBody);
        assert!(s.process(&bytes, &mut NoopHandler).is_err());
    }

    #[test]
    fn sdr_with_wrong_initiator_errors() {
        let mut s = fake_stage();
        // Build the ShareData envelope manually with a wrong initiator.
        // We can't reuse `wrap_client_share_data` because it always uses
        // `stage.user_channel_id`; mutating the SDR field after the
        // helper-built envelope would mean re-decoding and re-encoding,
        // which is more intrusive than just open-coding the construction.
        let pdu = ShutdownRequestPdu;
        let inner_size = pdu.size();
        let sd_total = SHARE_DATA_HEADER_SIZE + inner_size;
        let sc_total = SHARE_CONTROL_HEADER_SIZE + sd_total;
        let mut sc_payload = vec![0u8; sc_total];
        {
            let mut c = WriteCursor::new(&mut sc_payload);
            ShareControlHeader {
                total_length: sc_total as u16,
                pdu_type: ShareControlPduType::Data,
                pdu_source: s.user_channel_id,
            }
            .encode(&mut c)
            .unwrap();
            ShareDataHeader {
                share_id: s.share_id,
                stream_id: STREAM_LOW,
                uncompressed_length: inner_size as u16,
                pdu_type2: ShareDataPduType::ShutdownRequest,
                compressed_type: 0,
                compressed_length: 0,
            }
            .encode(&mut c)
            .unwrap();
            pdu.encode(&mut c).unwrap();
        }
        let sdr = SendDataRequest {
            initiator: s.user_channel_id + 1, // wrong!
            channel_id: s.io_channel_id,
            user_data: &sc_payload,
        };
        let payload_size = DATA_TRANSFER_HEADER_SIZE + sdr.size();
        let total = TPKT_HEADER_SIZE + payload_size;
        let mut buf = vec![0u8; total];
        {
            let mut c = WriteCursor::new(&mut buf);
            TpktHeader::try_for_payload(payload_size).unwrap().encode(&mut c).unwrap();
            DataTransfer.encode(&mut c).unwrap();
            sdr.encode(&mut c).unwrap();
        }
        assert!(s.process(&buf, &mut NoopHandler).is_err());
    }

    /// Wrap a single SVC chunk (`ChannelPduHeader` + chunk bytes) in
    /// the full TPKT/X.224/MCS/SDR envelope. Used by the inbound SVC
    /// reassembly tests below.
    fn wrap_client_svc_chunk(
        stage: &ServerActiveStage,
        channel_id: u16,
        flags: u32,
        total_length: u32,
        chunk: &[u8],
    ) -> Vec<u8> {
        let mut body = vec![0u8; CHANNEL_PDU_HEADER_SIZE + chunk.len()];
        {
            let mut c = WriteCursor::new(&mut body);
            ChannelPduHeader { length: total_length, flags }.encode(&mut c).unwrap();
            c.write_slice(chunk, "chunk").unwrap();
        }
        let sdr = SendDataRequest {
            initiator: stage.user_channel_id,
            channel_id,
            user_data: &body,
        };
        let payload_size = DATA_TRANSFER_HEADER_SIZE + sdr.size();
        let total = TPKT_HEADER_SIZE + payload_size;
        let mut buf = vec![0u8; total];
        {
            let mut c = WriteCursor::new(&mut buf);
            TpktHeader::try_for_payload(payload_size).unwrap().encode(&mut c).unwrap();
            DataTransfer.encode(&mut c).unwrap();
            sdr.encode(&mut c).unwrap();
        }
        buf
    }

    #[test]
    fn svc_single_chunk_emits_payload() {
        let mut s = fake_stage();
        let payload = b"hello, rdpsnd";
        let bytes = wrap_client_svc_chunk(
            &s,
            0x03EC,
            CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST,
            payload.len() as u32,
            payload,
        );
        let out = s.process(&bytes, &mut NoopHandler).unwrap();
        assert_eq!(
            out,
            vec![ActiveStageOutput::SvcData {
                channel_id: 0x03EC,
                payload: payload.to_vec(),
            }]
        );
    }

    #[test]
    fn svc_multi_chunk_reassembles() {
        let mut s = fake_stage();
        let full: Vec<u8> = (0..255u8).cycle().take(2000).collect();
        // Three chunks: FIRST(800) + middle(800) + LAST(400)
        let f1 = wrap_client_svc_chunk(&s, 0x03EC, CHANNEL_FLAG_FIRST, 2000, &full[..800]);
        let f2 = wrap_client_svc_chunk(&s, 0x03EC, 0, 2000, &full[800..1600]);
        let f3 = wrap_client_svc_chunk(&s, 0x03EC, CHANNEL_FLAG_LAST, 2000, &full[1600..2000]);
        // Intermediate chunks emit nothing.
        assert!(s.process(&f1, &mut NoopHandler).unwrap().is_empty());
        assert!(s.process(&f2, &mut NoopHandler).unwrap().is_empty());
        // LAST chunk emits the reassembled payload.
        let out = s.process(&f3, &mut NoopHandler).unwrap();
        assert_eq!(
            out,
            vec![ActiveStageOutput::SvcData {
                channel_id: 0x03EC,
                payload: full,
            }]
        );
    }

    #[test]
    fn svc_continuation_without_first_errors() {
        // A non-FIRST chunk arrives without any prior FIRST -- the
        // active stage MUST refuse rather than silently emit garbage.
        let mut s = fake_stage();
        let bytes = wrap_client_svc_chunk(&s, 0x03EC, 0, 100, &[0xAB; 50]);
        assert!(s.process(&bytes, &mut NoopHandler).is_err());
    }

    #[test]
    fn svc_compressed_chunk_rejected() {
        // CHANNEL_PACKET_COMPRESSED is in the high half of `flags` per
        // §2.2.6.1.1; the server skeleton has no bulk-decompression
        // support and MUST refuse rather than misinterpret the body.
        let mut s = fake_stage();
        let bytes = wrap_client_svc_chunk(
            &s,
            0x03EC,
            CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST | CHANNEL_PACKET_COMPRESSED,
            5,
            b"hello",
        );
        assert!(s.process(&bytes, &mut NoopHandler).is_err());
    }

    #[test]
    fn svc_first_chunk_with_oversized_total_rejected() {
        // C-1 regression: a single FIRST chunk declaring length =
        // 0xFFFF_FFFF MUST be refused before reaching `Vec::reserve`,
        // otherwise the server would attempt a 4 GiB allocation per
        // channel from one packet.
        let mut s = fake_stage();
        let bytes = wrap_client_svc_chunk(
            &s,
            0x03EC,
            CHANNEL_FLAG_FIRST,
            u32::MAX,
            &[0; 10],
        );
        let err = s.process(&bytes, &mut NoopHandler).unwrap_err();
        assert!(
            alloc::format!("{err}").contains("MAX_SVC_REASSEMBLY_BYTES"),
            "got: {err}"
        );
    }

    #[test]
    fn svc_single_chunk_with_oversized_total_rejected() {
        // C-1 regression for the FIRST | LAST single-chunk path.
        let mut s = fake_stage();
        let bytes = wrap_client_svc_chunk(
            &s,
            0x03EC,
            CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST,
            u32::MAX,
            &[0; 10],
        );
        let err = s.process(&bytes, &mut NoopHandler).unwrap_err();
        assert!(
            alloc::format!("{err}").contains("MAX_SVC_REASSEMBLY_BYTES"),
            "got: {err}"
        );
    }

    #[test]
    fn svc_lone_continuation_does_not_create_state() {
        // C-2 regression: a NEXT chunk arriving without any preceding
        // FIRST MUST NOT add an empty entry to `svc_reassembly`. Send
        // the same continuation 100 times across distinct channels (we
        // only have one VC in fake_result, so use the same one) and
        // assert the buffer count stays at zero.
        let mut s = fake_stage();
        for _ in 0..100 {
            let bytes = wrap_client_svc_chunk(&s, 0x03EC, 0, 100, &[0; 50]);
            assert!(s.process(&bytes, &mut NoopHandler).is_err());
        }
        assert!(s.svc_reassembly.is_empty());
    }

    #[test]
    fn svc_total_length_mismatch_rejected_on_last() {
        // FIRST declares total = 100 but LAST arrives with only 60
        // bytes accumulated. The active stage MUST detect the truncation.
        let mut s = fake_stage();
        let f1 = wrap_client_svc_chunk(&s, 0x03EC, CHANNEL_FLAG_FIRST, 100, &[0; 30]);
        let f2 = wrap_client_svc_chunk(&s, 0x03EC, CHANNEL_FLAG_LAST, 100, &[0; 30]);
        assert!(s.process(&f1, &mut NoopHandler).unwrap().is_empty());
        assert!(s.process(&f2, &mut NoopHandler).is_err());
    }

    #[test]
    fn encode_svc_send_single_chunk() {
        let s = fake_stage();
        let payload = b"audio data";
        let frames = s.encode_svc_send(0x03EC, payload).unwrap();
        assert_eq!(frames.len(), 1);
        // Decode the frame back and verify the chunk header carries
        // FIRST | LAST and the same total length.
        let mut c = ReadCursor::new(&frames[0]);
        let _tpkt = TpktHeader::decode(&mut c).unwrap();
        let _dt = DataTransfer::decode(&mut c).unwrap();
        let sdi = SendDataIndication::decode(&mut c).unwrap();
        assert_eq!(sdi.channel_id, 0x03EC);
        let mut inner = ReadCursor::new(sdi.user_data);
        let header = ChannelPduHeader::decode(&mut inner).unwrap();
        assert_eq!(header.length as usize, payload.len());
        assert_eq!(header.flags, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST);
        assert_eq!(inner.peek_remaining(), payload);
    }

    #[test]
    fn encode_svc_send_chunks_large_payload() {
        // Build a stage whose chunk_length is small so we can force
        // fragmentation without a 1600-byte payload. 64 is well above
        // the 8-byte minimum and well below the channel chunk limit.
        let cfg = RdpServerConfig::builder()
            .channel_chunk_length(64)
            .build()
            .unwrap();
        let s = ServerActiveStage::new(fake_result(), cfg);
        let payload: Vec<u8> = (0..200u8).collect(); // 200 bytes
        let frames = s.encode_svc_send(0x03EC, &payload).unwrap();
        // 200 / 64 = 3 chunks (64 + 64 + 64 + 8) → ceil = 4
        assert_eq!(frames.len(), 4);

        // Inspect each frame's header: FIRST on first, LAST on last,
        // neither on middles. `length` field is the same across all
        // chunks (= total uncompressed message size).
        let mut decoded_payload = Vec::new();
        for (idx, frame) in frames.iter().enumerate() {
            let mut c = ReadCursor::new(frame);
            let _tpkt = TpktHeader::decode(&mut c).unwrap();
            let _dt = DataTransfer::decode(&mut c).unwrap();
            let sdi = SendDataIndication::decode(&mut c).unwrap();
            let mut inner = ReadCursor::new(sdi.user_data);
            let h = ChannelPduHeader::decode(&mut inner).unwrap();
            assert_eq!(h.length as usize, payload.len(), "total length on chunk {idx}");
            let want_first = idx == 0;
            let want_last = idx == frames.len() - 1;
            assert_eq!((h.flags & CHANNEL_FLAG_FIRST) != 0, want_first, "FIRST on {idx}");
            assert_eq!((h.flags & CHANNEL_FLAG_LAST) != 0, want_last, "LAST on {idx}");
            decoded_payload.extend_from_slice(inner.peek_remaining());
        }
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn encode_svc_send_unknown_channel_errors() {
        let s = fake_stage();
        // 0x0FFF is not in the registered channel_ids of fake_result().
        assert!(s.encode_svc_send(0x0FFF, b"x").is_err());
    }

    #[test]
    fn encode_disconnect_emits_setting_then_ultimatum() {
        let s = fake_stage();
        let frames = s
            .encode_disconnect(ErrorInfoCode::RpcInitiatedDisconnect)
            .unwrap();
        assert_eq!(frames.len(), 2);

        // Frame 0: SetErrorInfoPdu wrapped in ShareData on I/O channel.
        let mut c = ReadCursor::new(&frames[0]);
        let _tpkt = TpktHeader::decode(&mut c).unwrap();
        let _dt = DataTransfer::decode(&mut c).unwrap();
        let sdi = SendDataIndication::decode(&mut c).unwrap();
        assert_eq!(sdi.channel_id, s.io_channel_id);
        assert_eq!(sdi.initiator, s.user_channel_id);
        let mut inner = ReadCursor::new(sdi.user_data);
        let sc = ShareControlHeader::decode(&mut inner).unwrap();
        assert_eq!(sc.pdu_type, ShareControlPduType::Data);
        assert_eq!(sc.pdu_source, s.user_channel_id);
        let sd = ShareDataHeader::decode(&mut inner).unwrap();
        assert_eq!(sd.pdu_type2, ShareDataPduType::SetErrorInfo);
        assert_eq!(sd.share_id, s.share_id);
        let info = SetErrorInfoPdu::decode(&mut ReadCursor::new(inner.peek_remaining())).unwrap();
        assert_eq!(info.code(), ErrorInfoCode::RpcInitiatedDisconnect);

        // Frame 1: top-level DisconnectProviderUltimatum (no MCS SDI
        // wrapping -- the PER body sits directly under X.224 DT).
        let mut c = ReadCursor::new(&frames[1]);
        let _tpkt = TpktHeader::decode(&mut c).unwrap();
        let _dt = DataTransfer::decode(&mut c).unwrap();
        let ult = DisconnectProviderUltimatum::decode(&mut c).unwrap();
        assert_eq!(ult.reason, DisconnectReason::UserRequested);
    }

    #[test]
    fn encode_disconnect_ultimatum_alone_decodes_back() {
        let s = fake_stage();
        let bytes = s
            .encode_disconnect_ultimatum(DisconnectReason::ProviderInitiated)
            .unwrap();
        let mut c = ReadCursor::new(&bytes);
        let _tpkt = TpktHeader::decode(&mut c).unwrap();
        let _dt = DataTransfer::decode(&mut c).unwrap();
        let ult = DisconnectProviderUltimatum::decode(&mut c).unwrap();
        assert_eq!(ult.reason, DisconnectReason::ProviderInitiated);
    }

    /// Wire-roundtrip smoke: drive the full `process()` dispatch
    /// against a known good fixture sequence (Suppress → Refresh →
    /// Shutdown) and assert each step produces the expected output. A
    /// proper TCP-loopback integration test against `justrdp-blocking`
    /// is out of scope for §11.2a (would need a no-TLS handshake
    /// shim and dual-thread driver) -- tracked as a §11.2a follow-up.
    #[test]
    fn session_smoke_test_dispatches_in_order() {
        let mut s = fake_stage();
        let mut h = NoopHandler;

        // Step 1: client suppresses output.
        let suppress_pdu = SuppressOutputPdu {
            allow_display_updates: 0,
            left: None,
            top: None,
            right: None,
            bottom: None,
        };
        let bytes = wrap_client_share_data(&s, ShareDataPduType::SuppressOutput, &suppress_pdu);
        let out = s.process(&bytes, &mut h).unwrap();
        assert!(matches!(
            out.as_slice(),
            [ActiveStageOutput::SuppressOutput { suppress: true, .. }]
        ));
        assert!(s.is_output_suppressed());

        // Step 2: client refreshes a region.
        let refresh = RefreshRectPdu {
            areas: alloc::vec![InclusiveRect { left: 0, top: 0, right: 99, bottom: 99 }],
        };
        let bytes = wrap_client_share_data(&s, ShareDataPduType::RefreshRect, &refresh);
        let out = s.process(&bytes, &mut h).unwrap();
        assert!(matches!(out.as_slice(), [ActiveStageOutput::RefreshRect(_)]));

        // Step 3: client requests shutdown -- server replies denied + notifies.
        let bytes = wrap_client_share_data(&s, ShareDataPduType::ShutdownRequest, &ShutdownRequestPdu);
        let out = s.process(&bytes, &mut h).unwrap();
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], ActiveStageOutput::SendBytes(_)));
        assert!(matches!(out[1], ActiveStageOutput::ShutdownRequested));

        // Step 4: server-initiated disconnect (LogoffByUser).
        let frames = s.encode_disconnect(ErrorInfoCode::LogoffByUser).unwrap();
        assert_eq!(frames.len(), 2);
        // Decode frame 0 SetErrorInfoPdu code matches.
        let mut c = ReadCursor::new(&frames[0]);
        let _ = TpktHeader::decode(&mut c).unwrap();
        let _ = DataTransfer::decode(&mut c).unwrap();
        let sdi = SendDataIndication::decode(&mut c).unwrap();
        let mut inner = ReadCursor::new(sdi.user_data);
        let _sc = ShareControlHeader::decode(&mut inner).unwrap();
        let _sd = ShareDataHeader::decode(&mut inner).unwrap();
        let info = SetErrorInfoPdu::decode(&mut ReadCursor::new(inner.peek_remaining())).unwrap();
        assert_eq!(info.code(), ErrorInfoCode::LogoffByUser);
    }

    #[test]
    fn encode_svc_send_empty_payload_emits_one_chunk() {
        let s = fake_stage();
        let frames = s.encode_svc_send(0x03EC, &[]).unwrap();
        assert_eq!(frames.len(), 1);
        let mut c = ReadCursor::new(&frames[0]);
        let _ = TpktHeader::decode(&mut c).unwrap();
        let _ = DataTransfer::decode(&mut c).unwrap();
        let sdi = SendDataIndication::decode(&mut c).unwrap();
        let mut inner = ReadCursor::new(sdi.user_data);
        let h = ChannelPduHeader::decode(&mut inner).unwrap();
        assert_eq!(h.length, 0);
        assert_eq!(h.flags, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST);
        assert_eq!(inner.peek_remaining(), &[] as &[u8]);
    }

    /// Empty PDU body used when only the dispatch table needs exercising.
    struct EmptyBody;
    impl Encode for EmptyBody {
        fn encode(&self, _: &mut WriteCursor<'_>) -> EncodeResult<()> {
            Ok(())
        }
        fn name(&self) -> &'static str {
            "EmptyBody"
        }
        fn size(&self) -> usize {
            0
        }
    }
}
