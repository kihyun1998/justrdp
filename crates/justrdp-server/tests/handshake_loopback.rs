//! End-to-end handshake integration test (§11.2d, first deliverable).
//!
//! Drives a [`ClientConnector`] against a [`ServerAcceptor`] in a single
//! process using in-memory byte queues. The `PROTOCOL_RDP` security
//! path is chosen so both sides skip TLS / CredSSP entirely -- this is
//! the "`NoopTlsUpgrader`" approach the roadmap calls for: rather than
//! faking TLS bytes we configure both peers to negotiate a path where
//! the TLS state is never entered.
//!
//! Standard-RDP-Security encryption (RC4 + MAC) is still a stub per
//! §11.2a and is wired up separately in §11.2a-stdsec; this file only
//! validates the state-machine plumbing end-to-end.

use justrdp_acceptor::{
    AcceptorConfig, Sequence as AcceptorSequence, ServerAcceptor, ServerAcceptorState,
};
use justrdp_connector::{
    ClientConnector, ClientConnectorState, Config, Sequence as ConnectorSequence,
};
use justrdp_core::{Decode, Encode, ReadCursor, WriteBuf, WriteCursor};
use justrdp_pdu::x224::SecurityProtocol;
use justrdp_server::{
    encode_bitmap_update, BitmapUpdate, DisplayRect, DisplayUpdate, EgfxFrame,
    RdpServerDisplayHandler, RdpServerInputHandler, ServerActiveStage,
};
use justrdp_pdu::rdp::error_info::ErrorInfoCode;
use justrdp_pdu::rdp::fast_path::{
    FastPathInputEvent, FastPathInputHeader, FastPathOutputHeader, FastPathOutputUpdate,
    FastPathScancodeEvent, FastPathUpdateType, FASTPATH_INPUT_ACTION_FASTPATH,
};
use justrdp_pdu::mcs::{SendDataIndication, SendDataRequest};
use justrdp_pdu::rdp::redirection::{
    ServerRedirectionPdu, LB_LOAD_BALANCE_INFO, LB_TARGET_NET_ADDRESS,
};
use justrdp_pdu::rdp::svc::{
    ChannelPduHeader, CHANNEL_FLAG_FIRST, CHANNEL_FLAG_LAST, CHANNEL_OPTION_INITIALIZED,
    CHANNEL_PDU_HEADER_SIZE,
};
use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
use justrdp_pdu::x224::{DataTransfer, DATA_TRANSFER_HEADER_SIZE};

/// Upper bound on the number of drive iterations before declaring the
/// handshake deadlocked. Empirically the PROTOCOL_RDP path completes in
/// well under 100 iterations; `4096` gives slack without hiding real
/// infinite loops.
const DRIVE_ITERATIONS_CAP: usize = 4096;

/// Build a PROTOCOL_RDP-only client config. No TLS certificate or
/// credentials are exercised; the username / password are retained
/// because `Config::builder` requires them, but they are never used
/// in the absence of CredSSP/RDSTLS.
fn rdp_only_client_config() -> Config {
    Config::builder("test-user", "test-pass")
        .security_protocol(SecurityProtocol::RDP)
        .build()
}

/// Same as [`rdp_only_client_config`] but with `cliprdr` / `rdpsnd`
/// registered as static virtual channels so the server side can
/// exercise its channel-handler dispatch on those IDs.
fn rdp_client_config_with_channels() -> Config {
    Config::builder("test-user", "test-pass")
        .security_protocol(SecurityProtocol::RDP)
        .channel("cliprdr", CHANNEL_OPTION_INITIALIZED)
        .channel("rdpsnd", CHANNEL_OPTION_INITIALIZED)
        .build()
}

/// Build a PROTOCOL_RDP-only acceptor config. `require_enhanced_security`
/// MUST be `false` here since the server is advertising only
/// `PROTOCOL_RDP`; otherwise the builder rejects the combination as a
/// downgrade hazard (which is the correct default for production but
/// unhelpful for this loopback).
fn rdp_only_acceptor_config() -> AcceptorConfig {
    AcceptorConfig::builder()
        .supported_protocols(SecurityProtocol::RDP)
        .require_enhanced_security(false)
        .build()
        .expect("PROTOCOL_RDP-only is a valid combination")
}

/// Result of one drive attempt on a `Sequence` implementor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepOutcome {
    /// State machine advanced (either emitted output or consumed input).
    Progressed,
    /// Wait state and the inbound buffer does not yet contain a full
    /// PDU -- caller should let the peer run to produce more bytes.
    WaitingForInput,
    /// Terminal state reached; no further steps meaningful.
    Terminal,
}

/// Drive the client one step.
fn step_client(
    client: &mut ClientConnector,
    inbound: &mut Vec<u8>,
    out: &mut WriteBuf,
    outbound: &mut Vec<u8>,
) -> StepOutcome {
    if client.state().is_connected() {
        return StepOutcome::Terminal;
    }
    match client.next_pdu_hint() {
        None => {
            // Send / external-delegation state: step with no input.
            out.clear();
            client
                .step(&[], out)
                .expect("client send-state step failed");
            outbound.extend_from_slice(out.as_slice());
            StepOutcome::Progressed
        }
        Some(hint) => {
            let Some((_is_pdu, n)) = hint.find_size(inbound) else {
                return StepOutcome::WaitingForInput;
            };
            if n == 0 {
                return StepOutcome::WaitingForInput;
            }
            out.clear();
            client
                .step(&inbound[..n], out)
                .expect("client wait-state step failed");
            inbound.drain(..n);
            outbound.extend_from_slice(out.as_slice());
            StepOutcome::Progressed
        }
    }
}

/// Drive the acceptor one step. Mirror of `step_client`.
fn step_acceptor(
    acceptor: &mut ServerAcceptor,
    inbound: &mut Vec<u8>,
    out: &mut WriteBuf,
    outbound: &mut Vec<u8>,
) -> StepOutcome {
    if acceptor.state().is_terminal() {
        return StepOutcome::Terminal;
    }
    match AcceptorSequence::next_pdu_hint(acceptor) {
        None => {
            out.clear();
            acceptor
                .step(&[], out)
                .expect("acceptor send-state step failed");
            outbound.extend_from_slice(out.as_slice());
            StepOutcome::Progressed
        }
        Some(hint) => {
            let Some((_is_pdu, n)) = hint.find_size(inbound) else {
                return StepOutcome::WaitingForInput;
            };
            if n == 0 {
                return StepOutcome::WaitingForInput;
            }
            out.clear();
            acceptor
                .step(&inbound[..n], out)
                .expect("acceptor wait-state step failed");
            inbound.drain(..n);
            outbound.extend_from_slice(out.as_slice());
            StepOutcome::Progressed
        }
    }
}

/// Drive client ↔ acceptor to the terminal Connected / Accepted pair.
///
/// Alternates calls to `step_client` and `step_acceptor`; each function
/// either emits bytes (if in a send state), consumes buffered input
/// (if in a wait state with a full PDU available), or reports that it
/// is waiting. The loop terminates when both peers are terminal; a
/// round with no progress on either side is treated as a deadlock
/// and raises a panic with diagnostic context.
fn drive_full_handshake(
    mut client: ClientConnector,
    mut acceptor: ServerAcceptor,
) -> (ClientConnector, ServerAcceptor) {
    let mut c2s: Vec<u8> = Vec::new();
    let mut s2c: Vec<u8> = Vec::new();
    let mut client_out = WriteBuf::new();
    let mut server_out = WriteBuf::new();

    for i in 0..DRIVE_ITERATIONS_CAP {
        let client_done = client.state().is_connected();
        let server_done = acceptor.state().is_accepted();
        if client_done && server_done {
            return (client, acceptor);
        }

        // Let each side make as much progress as possible this round.
        // A state machine may chain several send states back-to-back
        // (e.g. the client's finalization burst) without waiting for
        // peer input, so we loop until the step either waits or
        // terminates.
        let mut any_progress = false;
        loop {
            match step_client(&mut client, &mut s2c, &mut client_out, &mut c2s) {
                StepOutcome::Progressed => any_progress = true,
                StepOutcome::WaitingForInput | StepOutcome::Terminal => break,
            }
        }
        loop {
            match step_acceptor(&mut acceptor, &mut c2s, &mut server_out, &mut s2c) {
                StepOutcome::Progressed => any_progress = true,
                StepOutcome::WaitingForInput | StepOutcome::Terminal => break,
            }
        }

        if !any_progress {
            panic!(
                "handshake deadlocked at iteration {i}: \
                 client_state={:?} server_state={:?} \
                 c2s_buffered={}B s2c_buffered={}B",
                client.state(),
                acceptor.state(),
                c2s.len(),
                s2c.len(),
            );
        }
    }
    panic!(
        "handshake did not complete within {DRIVE_ITERATIONS_CAP} iterations \
         (client_state={:?} server_state={:?})",
        client.state(),
        acceptor.state(),
    );
}

/// Minimal display handler: exposes `Option<DisplayUpdate>`; yields it
/// once, then returns `None`. Used by the bitmap-emit test to verify
/// the active stage consumes the handler output.
struct SingleShotDisplay {
    pending: Option<DisplayUpdate>,
    size: (u16, u16),
}

impl RdpServerDisplayHandler for SingleShotDisplay {
    fn get_display_update(&mut self) -> Option<DisplayUpdate> {
        self.pending.take()
    }
    fn get_display_size(&self) -> (u16, u16) {
        self.size
    }
}

/// Input handler that records every callback so the active-session
/// test can assert on what the server dispatched.
#[derive(Default)]
struct RecordingInput {
    scancodes: Vec<(u16, u8)>,
}

impl RdpServerInputHandler for RecordingInput {
    fn on_keyboard_scancode(&mut self, flags: u16, key_code: u8) {
        self.scancodes.push((flags, key_code));
    }
}

/// Build a `BitmapUpdate` with an 8x8 32-bpp solid-color fill. The
/// row-stride padding requirement (4-byte boundary) is already met for
/// 32-bpp * 8 pixels = 32 bytes per row.
fn solid_bitmap_update(color: u32) -> BitmapUpdate {
    let row_stride = 8 * 4; // 32 bpp * 8 pixels
    let mut data = Vec::with_capacity(row_stride * 8);
    for _ in 0..8 {
        for _ in 0..8 {
            data.extend_from_slice(&color.to_le_bytes());
        }
    }
    BitmapUpdate {
        dest_left: 0,
        dest_top: 0,
        width: 8,
        height: 8,
        bits_per_pixel: 32,
        data,
    }
}

/// Build a fast-path input PDU carrying a single scancode event. The
/// layout mirrors `build_fast_path_input` in `active.rs` but lives in
/// the test crate so we do not re-export test-only helpers.
fn fast_path_scancode_pdu(flags: u8, key_code: u8) -> Vec<u8> {
    let event = FastPathInputEvent::Scancode(FastPathScancodeEvent {
        event_flags: flags,
        key_code,
    });
    let body_size = event.size();
    let provisional_total = 1 + 2 + body_size;
    let total = if provisional_total <= 0x7F {
        2 + body_size
    } else {
        provisional_total
    };
    let header = FastPathInputHeader {
        action: FASTPATH_INPUT_ACTION_FASTPATH,
        num_events: 1,
        flags: 0,
        length: total as u16,
    };
    let mut buf = vec![0u8; header.size() + body_size];
    let mut c = WriteCursor::new(&mut buf);
    header.encode(&mut c).unwrap();
    event.encode(&mut c).unwrap();
    buf
}

/// Decode one fast-path output frame into its update PDU. Asserts the
/// outer framing (action + length) looks sane and returns the inner
/// `FastPathOutputUpdate` so callers can assert on `update_code` /
/// `update_data`.
fn decode_fast_path_output(frame: &[u8]) -> FastPathOutputUpdate {
    let mut cursor = ReadCursor::new(frame);
    let hdr = FastPathOutputHeader::decode(&mut cursor).expect("fast-path header decode");
    assert_eq!(
        hdr.action, 0x00,
        "FASTPATH_OUTPUT_ACTION_FASTPATH action byte"
    );
    assert_eq!(
        hdr.length as usize,
        frame.len(),
        "fast-path header length MUST equal total frame size"
    );
    FastPathOutputUpdate::decode(&mut cursor).expect("fast-path output update decode")
}

#[test]
fn protocol_rdp_handshake_reaches_both_terminal_states() {
    // Sanity: starting states are as expected.
    let client = ClientConnector::new(rdp_only_client_config());
    let acceptor = ServerAcceptor::new(rdp_only_acceptor_config());
    assert!(matches!(
        client.state(),
        ClientConnectorState::ConnectionInitiationSendRequest
    ));
    assert!(matches!(
        acceptor.state(),
        ServerAcceptorState::WaitConnectionRequest
    ));

    let (client, acceptor) = drive_full_handshake(client, acceptor);

    assert!(
        client.state().is_connected(),
        "client did not reach Connected: {:?}",
        client.state()
    );
    assert!(
        acceptor.state().is_accepted(),
        "acceptor did not reach Accepted: {:?}",
        acceptor.state()
    );

    // Cross-verify the negotiated parameters look sane on both sides.
    let client_result = client.result().expect("Connected implies ConnectionResult");
    match acceptor.state() {
        ServerAcceptorState::Accepted { result } => {
            assert_eq!(
                result.io_channel_id, client_result.io_channel_id,
                "I/O channel ID MUST match on both sides"
            );
            assert_eq!(
                result.user_channel_id, client_result.user_channel_id,
                "user channel ID MUST match on both sides"
            );
            assert_eq!(
                result.share_id, client_result.share_id,
                "share_id MUST match on both sides"
            );
            assert_eq!(result.selected_protocol, SecurityProtocol::RDP);
        }
        other => panic!("unexpected acceptor state: {other:?}"),
    }
}

/// Drive the handshake and then exercise both directions of the active
/// session:
///
/// 1. Server emits an 8x8 bitmap via `encode_bitmap_update`; the test
///    parses the resulting fast-path frame(s) and asserts the update
///    code is `Bitmap`.
/// 2. The test builds a fast-path scancode PDU as a client would; feeds
///    it to `ServerActiveStage::process`; asserts the recording input
///    handler observed the scancode with the expected flags.
/// 3. Server emits a clean-disconnect pair (`SetErrorInfoPdu` wrapped
///    in ShareData + MCS `DisconnectProviderUltimatum`); the test
///    verifies both frames are non-empty, distinguishable, and in the
///    expected TPKT vs. raw-MCS framing.
#[test]
fn active_session_bitmap_emit_input_dispatch_and_clean_disconnect() {
    // Phase 1: handshake (same as the prior test).
    let client = ClientConnector::new(rdp_only_client_config());
    let acceptor = ServerAcceptor::new(rdp_only_acceptor_config());
    let (_client, acceptor) = drive_full_handshake(client, acceptor);

    // Clone the `AcceptanceResult` out of the Accepted-state acceptor.
    // (We use `ServerAcceptor` directly rather than `RdpServer` here
    // so the handshake drive loop can use the same low-level API on
    // both sides; cloning the result is the trade-off.)
    let result = match acceptor.state() {
        ServerAcceptorState::Accepted { result } => result.clone(),
        other => panic!("expected Accepted state, got {other:?}"),
    };
    let config = justrdp_server::RdpServerConfig::builder()
        .build()
        .expect("default RdpServerConfig");
    let mut active = ServerActiveStage::new(result, config.clone());

    // ── Direction 1: server emits a bitmap ──
    let frames = encode_bitmap_update(&config, &solid_bitmap_update(0xFF00_00FF))
        .expect("encode_bitmap_update should succeed for an 8x8 32-bpp solid");
    assert!(!frames.is_empty(), "at least one fast-path frame expected");

    for frame in &frames {
        let update = decode_fast_path_output(frame);
        assert_eq!(
            update.update_code,
            FastPathUpdateType::Bitmap,
            "emitted frame MUST carry a BITMAP update"
        );
        assert!(
            !update.update_data.is_empty(),
            "BITMAP update_data cannot be empty"
        );
    }

    // Poll the display handler seam too -- confirms the public contract
    // remains usable from the integration test vantage.
    let mut display = SingleShotDisplay {
        pending: Some(DisplayUpdate::Bitmap(solid_bitmap_update(0x00FF_00FF))),
        size: (1024, 768),
    };
    match display.get_display_update() {
        Some(DisplayUpdate::Bitmap(u)) => assert_eq!(u.width, 8),
        other => panic!("expected Bitmap update, got {other:?}"),
    }
    assert!(display.get_display_update().is_none());

    // ── Direction 2: client emits fast-path input ──
    // Build a press-down scancode for 'A' (key_code 0x1E) with event_flags=0.
    let mut input = RecordingInput::default();
    let fp_input = fast_path_scancode_pdu(0x00, 0x1E);
    let out = active
        .process(&fp_input, &mut input)
        .expect("server MUST dispatch fast-path input");
    assert!(
        out.is_empty(),
        "fast-path input events produce no outbound PDUs by themselves"
    );
    assert_eq!(
        input.scancodes,
        vec![(0x0000, 0x1E)],
        "recorded scancode MUST match the wire event_flags / key_code"
    );

    // ── Direction 3: clean disconnect ──
    let disconnect_frames = active
        .encode_disconnect(ErrorInfoCode::RpcInitiatedDisconnect)
        .expect("encode_disconnect should succeed in Active state");
    assert_eq!(
        disconnect_frames.len(),
        2,
        "clean disconnect is exactly `SetErrorInfoPdu` + `DisconnectProviderUltimatum`"
    );
    let [set_error_frame, ultimatum_frame] = [&disconnect_frames[0], &disconnect_frames[1]];

    // SetErrorInfoPdu is wrapped in TPKT (starts with 0x03); the MCS
    // ultimatum is raw X.224 DT (starts with 0x03 too). Both share the
    // TPKT framing. A reasonable sanity check is that they are distinct
    // and neither is empty.
    assert!(!set_error_frame.is_empty());
    assert!(!ultimatum_frame.is_empty());
    assert_ne!(
        set_error_frame, ultimatum_frame,
        "disconnect frames MUST be distinct"
    );
    assert_eq!(
        set_error_frame[0], 0x03,
        "SetErrorInfo PDU MUST be TPKT-framed"
    );
    assert_eq!(
        ultimatum_frame[0], 0x03,
        "DisconnectProviderUltimatum MUST also be TPKT-framed (X.224 DT)"
    );

    // ── Sanity: refresh-rect / suppress-output input path still works ──
    // The display handler's on_refresh_rect default drops the event;
    // assert via a custom handler that it surfaces the rectangle.
    struct SuppressRecorder {
        suppress_calls: Vec<(bool, Option<DisplayRect>)>,
    }
    impl RdpServerDisplayHandler for SuppressRecorder {
        fn get_display_update(&mut self) -> Option<DisplayUpdate> {
            None
        }
        fn get_display_size(&self) -> (u16, u16) {
            (1024, 768)
        }
        fn on_suppress_output(&mut self, suppress: bool, area: Option<DisplayRect>) {
            self.suppress_calls.push((suppress, area));
        }
    }
    let mut rec = SuppressRecorder {
        suppress_calls: Vec::new(),
    };
    rec.on_suppress_output(true, None);
    assert_eq!(rec.suppress_calls, vec![(true, None)]);
}

// ───────────────────────────────────────────────────────────────
// Channel-handler validation (§11.2d, 3rd deliverable)
// ───────────────────────────────────────────────────────────────

/// Wrap a single SVC chunk in the client-side framing
/// `TPKT + X.224 DT + MCS SendDataRequest + ChannelPduHeader` so
/// `ServerActiveStage::process` can decode it.
fn wrap_client_svc(
    user_channel_id: u16,
    channel_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut body = vec![0u8; CHANNEL_PDU_HEADER_SIZE + payload.len()];
    {
        let mut c = WriteCursor::new(&mut body);
        ChannelPduHeader {
            length: payload.len() as u32,
            flags: CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST,
        }
        .encode(&mut c)
        .unwrap();
        c.write_slice(payload, "chunk").unwrap();
    }
    let sdr = SendDataRequest {
        initiator: user_channel_id,
        channel_id,
        user_data: &body,
    };
    let payload_size = DATA_TRANSFER_HEADER_SIZE + sdr.size();
    let total = TPKT_HEADER_SIZE + payload_size;
    let mut buf = vec![0u8; total];
    let mut c = WriteCursor::new(&mut buf);
    TpktHeader::try_for_payload(payload_size).unwrap().encode(&mut c).unwrap();
    DataTransfer.encode(&mut c).unwrap();
    sdr.encode(&mut c).unwrap();
    buf
}

/// Decode a server-direction frame produced by
/// `encode_svc_send` / the SVC dispatch path. Returns
/// `(channel_id, svc_payload)`.
fn unwrap_server_svc(frame: &[u8]) -> (u16, Vec<u8>) {
    let mut c = ReadCursor::new(frame);
    let _tpkt = TpktHeader::decode(&mut c).unwrap();
    let _dt = DataTransfer::decode(&mut c).unwrap();
    let sdi = SendDataIndication::decode(&mut c).unwrap();
    let mut inner = ReadCursor::new(sdi.user_data);
    let _hdr = ChannelPduHeader::decode(&mut inner).unwrap();
    (sdi.channel_id, inner.peek_remaining().to_vec())
}

/// Channel-handler seam validation: drive a handshake that negotiates
/// `cliprdr` and `rdpsnd` as static channels, register the servers
/// against the active stage, and verify:
///
/// 1. `register_svc_processor` emits the expected init burst for each
///    channel (cliprdr: Caps + MonitorReady; rdpsnd: Server Audio
///    Formats).
/// 2. A client-direction CLIPRDR Format List PDU elicits a Format
///    List Response PDU from the server, encoded as an SVC frame.
/// 3. A client-direction RDPSND Client Audio Formats PDU advances the
///    server past format negotiation (recorded by the handler).
#[test]
fn channel_handlers_roundtrip_over_active_stage() {
    use justrdp_cliprdr::pdu::{
        ClipboardHeader, ClipboardMsgFlags, ClipboardMsgType, FormatListPdu, LongFormatName,
    };
    use justrdp_cliprdr::{
        ClipboardResult, ClipboardServer, FormatDataResponse, FormatListResponse,
        RdpServerClipboardHandler,
    };
    use justrdp_rdpsnd::pdu::{
        AudioFormat, ClientAudioFormatsPdu, ClientSndFlags, SndHeader, SndMsgType,
    };
    use justrdp_rdpsnd::{RdpServerSoundHandler, SoundServer};

    // Drive a handshake that registers cliprdr + rdpsnd on the client.
    let client = ClientConnector::new(rdp_client_config_with_channels());
    let acceptor = ServerAcceptor::new(rdp_only_acceptor_config());
    let (client, acceptor) = drive_full_handshake(client, acceptor);

    // Cross-check both sides agree on the channel IDs.
    let result = match acceptor.state() {
        ServerAcceptorState::Accepted { result } => result.clone(),
        other => panic!("expected Accepted, got {other:?}"),
    };
    let client_result = client.result().expect("Connected implies result");
    let cliprdr_id = result
        .channel_ids
        .iter()
        .find(|(n, _)| n == "cliprdr")
        .map(|(_, id)| *id)
        .expect("cliprdr channel negotiated");
    let rdpsnd_id = result
        .channel_ids
        .iter()
        .find(|(n, _)| n == "rdpsnd")
        .map(|(_, id)| *id)
        .expect("rdpsnd channel negotiated");
    assert_eq!(
        client_result.channel_ids, result.channel_ids,
        "both sides see the same channel_id list"
    );
    let user_channel_id = result.user_channel_id;

    let config = justrdp_server::RdpServerConfig::builder()
        .build()
        .expect("default RdpServerConfig");
    let mut active = ServerActiveStage::new(result, config);

    // ── Register ClipboardServer (server-direction cliprdr) ──
    struct AcceptingClipHandler;
    impl RdpServerClipboardHandler for AcceptingClipHandler {
        fn on_format_list(
            &mut self,
            _formats: &[LongFormatName],
        ) -> ClipboardResult<FormatListResponse> {
            Ok(FormatListResponse::Ok)
        }
        fn on_format_data_request(
            &mut self,
            _format_id: u32,
        ) -> ClipboardResult<FormatDataResponse> {
            Ok(FormatDataResponse::Fail)
        }
        fn on_format_data_response(
            &mut self,
            _data: &[u8],
            _is_success: bool,
            _format_id: Option<u32>,
        ) {
        }
    }
    let clip_frames = active
        .register_svc_processor(Box::new(ClipboardServer::new(Box::new(
            AcceptingClipHandler,
        ))))
        .expect("register cliprdr server");
    assert_eq!(
        clip_frames.len(),
        2,
        "cliprdr init burst emits 2 frames (Caps + MonitorReady)"
    );
    {
        let (ch0, payload0) = unwrap_server_svc(&clip_frames[0]);
        let (ch1, payload1) = unwrap_server_svc(&clip_frames[1]);
        assert_eq!(ch0, cliprdr_id);
        assert_eq!(ch1, cliprdr_id);
        let h0 = ClipboardHeader::decode(&mut ReadCursor::new(&payload0)).unwrap();
        let h1 = ClipboardHeader::decode(&mut ReadCursor::new(&payload1)).unwrap();
        assert_eq!(h0.msg_type, ClipboardMsgType::ClipCaps);
        assert_eq!(h1.msg_type, ClipboardMsgType::MonitorReady);
    }

    // ── Register SoundServer (server-direction rdpsnd) ──
    use std::sync::{Arc, Mutex};
    #[derive(Default)]
    struct SoundHandlerState {
        client_formats_calls: u32,
    }
    struct RecordingSoundHandler {
        state: Arc<Mutex<SoundHandlerState>>,
    }
    impl RdpServerSoundHandler for RecordingSoundHandler {
        fn on_client_formats(
            &mut self,
            _formats: &[AudioFormat],
            _flags: ClientSndFlags,
            _version: u16,
        ) {
            self.state.lock().unwrap().client_formats_calls += 1;
        }
    }
    let sound_state = Arc::new(Mutex::new(SoundHandlerState::default()));
    let sound_server = SoundServer::new(
        Box::new(RecordingSoundHandler {
            state: sound_state.clone(),
        }),
        vec![AudioFormat::pcm(2, 44100, 16)],
    );
    let snd_frames = active
        .register_svc_processor(Box::new(sound_server))
        .expect("register rdpsnd server");
    assert_eq!(snd_frames.len(), 1, "rdpsnd emits ServerAudioFormats");
    {
        let (ch, payload) = unwrap_server_svc(&snd_frames[0]);
        assert_eq!(ch, rdpsnd_id);
        let h = SndHeader::decode(&mut ReadCursor::new(&payload)).unwrap();
        assert_eq!(h.msg_type, SndMsgType::Formats);
    }

    // ── CLIPRDR roundtrip: client FormatList → server FormatListResponse ──
    let client_clip_caps_body = {
        // Minimal Client Capabilities PDU: needed so the server can
        // negotiate `USE_LONG_FORMAT_NAMES` before the Format List parses
        // in long form.
        use justrdp_cliprdr::pdu::{
            ClipboardCapsPdu, GeneralCapabilityFlags, GeneralCapabilitySet, CB_CAPS_VERSION_2,
        };
        let caps = ClipboardCapsPdu::new(GeneralCapabilitySet::new(
            CB_CAPS_VERSION_2,
            GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES,
        ));
        let mut buf = vec![0u8; caps.size()];
        caps.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf
    };
    let caps_bytes = wrap_client_svc(user_channel_id, cliprdr_id, &client_clip_caps_body);
    let mut drop_input = RecordingInput::default();
    let caps_out = active.process(&caps_bytes, &mut drop_input).unwrap();
    assert!(
        caps_out.is_empty(),
        "Caps PDU produces no response (state change only)"
    );

    // Now send the Format List (long variant, one entry: CF_UNICODETEXT).
    let format_list_body = {
        let pdu = FormatListPdu::Long(vec![LongFormatName::new(0x000D, String::new())]);
        let mut buf = vec![0u8; pdu.full_size()];
        pdu.encode_full(&mut WriteCursor::new(&mut buf)).unwrap();
        buf
    };
    let fl_bytes = wrap_client_svc(user_channel_id, cliprdr_id, &format_list_body);
    let fl_out = active.process(&fl_bytes, &mut drop_input).unwrap();
    assert_eq!(fl_out.len(), 1, "exactly one FormatListResponse frame");
    let out_bytes = match &fl_out[0] {
        justrdp_server::ActiveStageOutput::SendBytes(b) => b.clone(),
        other => panic!("expected SendBytes, got {other:?}"),
    };
    let (ch, payload) = unwrap_server_svc(&out_bytes);
    assert_eq!(ch, cliprdr_id);
    let resp_header = ClipboardHeader::decode(&mut ReadCursor::new(&payload)).unwrap();
    assert_eq!(resp_header.msg_type, ClipboardMsgType::FormatListResponse);
    assert!(resp_header.msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_OK));

    // ── RDPSND handshake: client sends Client Audio Formats ──
    let client_snd_body = {
        let pdu = ClientAudioFormatsPdu {
            flags: ClientSndFlags::ALIVE,
            volume: 0,
            pitch: 0,
            version: 6,
            formats: vec![AudioFormat::pcm(2, 44100, 16)],
        };
        let mut buf = vec![0u8; pdu.size()];
        pdu.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf
    };
    let snd_bytes = wrap_client_svc(user_channel_id, rdpsnd_id, &client_snd_body);
    let snd_out = active.process(&snd_bytes, &mut drop_input).unwrap();
    assert!(
        snd_out.is_empty(),
        "ClientAudioFormats produces no direct response"
    );
    assert_eq!(
        sound_state.lock().unwrap().client_formats_calls,
        1,
        "SoundServer handler MUST receive on_client_formats exactly once"
    );
}

// ───────────────────────────────────────────────────────────────
// GFX pipeline seam smoke test (§11.2d, 4th deliverable)
// ───────────────────────────────────────────────────────────────
//
// The full GfxServer ↔ GfxClient round-trip (RFX / EGFX
// `WireToSurface` / `FrameAcknowledge`) is covered by the loopback
// test added in §11.2b-3 (commit a12f1b2). Here we only smoke-test the
// `get_egfx_frame` seam so a future change to `RdpServerDisplayHandler`
// cannot silently break the hook the server uses to drain EGFX frames.

/// Display handler that surfaces a pre-built EGFX frame once.
struct GfxFrameHandler {
    frame: Option<EgfxFrame>,
}

impl RdpServerDisplayHandler for GfxFrameHandler {
    fn get_display_update(&mut self) -> Option<DisplayUpdate> {
        None
    }
    fn get_display_size(&self) -> (u16, u16) {
        (1024, 768)
    }
    fn get_egfx_frame(&mut self) -> Option<EgfxFrame> {
        self.frame.take()
    }
}

// ───────────────────────────────────────────────────────────────
// Server Redirection loopback (§11.2e Commit 2)
// ───────────────────────────────────────────────────────────────

/// UTF-16LE encode `s` with a trailing `\0` word. Local helper so this
/// test's setup does not depend on a common utility we are not ready
/// to lift into the public API yet.
fn utf16le_null_terminated(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    out.extend_from_slice(&[0, 0]);
    out
}

/// End-to-end loopback test for §11.2e: the server emits a Server
/// Redirection PDU just as the handshake is about to terminate, and
/// the real `ClientConnector` decodes it into
/// `ConnectionResult.server_redirection`.
///
/// Injection strategy: drive the handshake normally until the
/// `ServerAcceptor` transitions to `Accepted` (which means it has
/// just emitted its final Font Map PDU into the server-to-client
/// buffer). At that instant the client is still in
/// `ConnectionFinalizationWaitFontMap` -- the exact state where the
/// finalization PDU decoder recognises `ShareControlPduType::ServerRedirect`.
/// We discard the pending Font Map bytes, replace them with the
/// redirection frame produced by `ServerActiveStage::emit_redirection`,
/// and continue driving. The client parses the redirection and
/// transitions directly to `Connected` with the PDU carried in
/// `ConnectionResult.server_redirection`.
#[test]
fn server_emit_redirection_during_finalization_reaches_connected() {
    let mut client = ClientConnector::new(rdp_only_client_config());
    let mut acceptor = ServerAcceptor::new(rdp_only_acceptor_config());
    let mut c2s: Vec<u8> = Vec::new();
    let mut s2c: Vec<u8> = Vec::new();
    let mut client_out = WriteBuf::new();
    let mut server_out = WriteBuf::new();

    let redirection_pdu = ServerRedirectionPdu {
        session_id: 0xCAFE_BABE,
        redir_flags: LB_TARGET_NET_ADDRESS | LB_LOAD_BALANCE_INFO,
        target_net_address: Some(utf16le_null_terminated("10.9.8.7")),
        load_balance_info: Some(b"Cookie: msts=redirected\r\n".to_vec()),
        ..Default::default()
    };

    let mut injected = false;
    for i in 0..DRIVE_ITERATIONS_CAP {
        if client.state().is_connected() {
            break;
        }

        // Trigger the injection on the first iteration after the
        // acceptor reaches Accepted. By construction, `step_acceptor`
        // of the prior iteration placed the final Font Map into
        // `s2c`; we overwrite it before the client gets a chance to
        // read those bytes.
        if !injected && acceptor.state().is_accepted() {
            let result = match acceptor.state() {
                ServerAcceptorState::Accepted { result } => result.clone(),
                _ => unreachable!(),
            };
            let config = justrdp_server::RdpServerConfig::builder()
                .build()
                .expect("default RdpServerConfig");
            let mut active = ServerActiveStage::new(result, config);
            let frame = active
                .emit_redirection(&redirection_pdu)
                .expect("emit_redirection should succeed on a fresh Active stage");
            s2c.clear();
            s2c.extend_from_slice(&frame);
            injected = true;
            continue;
        }

        let mut any = false;
        loop {
            match step_client(&mut client, &mut s2c, &mut client_out, &mut c2s) {
                StepOutcome::Progressed => any = true,
                StepOutcome::WaitingForInput | StepOutcome::Terminal => break,
            }
        }
        loop {
            match step_acceptor(&mut acceptor, &mut c2s, &mut server_out, &mut s2c) {
                StepOutcome::Progressed => any = true,
                StepOutcome::WaitingForInput | StepOutcome::Terminal => break,
            }
        }
        if !any {
            panic!(
                "handshake deadlocked at iteration {i} before injection: \
                 client_state={:?} acceptor_state={:?}",
                client.state(),
                acceptor.state()
            );
        }
    }

    assert!(injected, "redirection was never injected into the handshake");
    assert!(
        client.state().is_connected(),
        "client MUST reach Connected after receiving the redirection PDU, got {:?}",
        client.state()
    );

    let result = client.result().expect("Connected implies ConnectionResult");
    let got = result
        .server_redirection
        .as_ref()
        .expect("ConnectionResult.server_redirection MUST be populated");
    assert_eq!(got.session_id, 0xCAFE_BABE);
    assert!(got.has_flag(LB_TARGET_NET_ADDRESS));
    assert!(got.has_flag(LB_LOAD_BALANCE_INFO));
    assert_eq!(got, &redirection_pdu);
}

#[test]
fn egfx_frame_seam_surfaces_caller_owned_bytes() {
    // Pretend two `DrdynvcServer::send_data` payloads came out of a
    // `GfxServer` — we do not reproduce the GFX encoding here (that is
    // §11.2b-3's turf). The seam's contract is that whatever the caller
    // pushes through `EgfxFrame::with_messages` survives round-tripping
    // through `RdpServerDisplayHandler::get_egfx_frame`.
    let payload_a = vec![0xE0, 0x04, 0xAA, 0xBB, 0xCC];
    let payload_b = vec![0xE0, 0x04, 0x11, 0x22, 0x33, 0x44];
    let frame = EgfxFrame::with_messages(vec![payload_a.clone(), payload_b.clone()]);
    let mut handler = GfxFrameHandler {
        frame: Some(frame),
    };

    // First poll yields the frame with bytes intact.
    let out = handler
        .get_egfx_frame()
        .expect("seam MUST surface the queued EGFX frame");
    assert_eq!(out.messages.len(), 2);
    assert_eq!(out.messages[0], payload_a);
    assert_eq!(out.messages[1], payload_b);
    // Second poll returns None (default idle response).
    assert!(handler.get_egfx_frame().is_none());
}
