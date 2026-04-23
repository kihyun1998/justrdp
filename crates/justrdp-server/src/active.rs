#![forbid(unsafe_code)]

//! `ServerActiveStage` -- post-`Accepted` session loop.
//!
//! This module implements the **server-side** half of the active RDP
//! session: it consumes complete client PDUs (TPKT-framed slow-path or
//! fast-path) and produces a stream of [`ActiveStageOutput`] events that
//! the caller routes to display / input handlers and to the network.
//!
//! Scope of this commit (Commit 5 of §11.2a) is **slow-path control PDU
//! dispatch only**:
//!
//! | `pduType2`              | Value | Behaviour                                         |
//! |-------------------------|------:|---------------------------------------------------|
//! | `Refresh Rect`          |  0x21 | emit [`ActiveStageOutput::RefreshRect`]           |
//! | `Suppress Output`       |  0x23 | track `suppress_output`, emit notification        |
//! | `Shutdown Request`      |  0x24 | emit `ShutdownDenied` reply + notification        |
//! | `Control(RequestCtrl)`  |  0x14 | emit `GrantedControl` reply (FreeRDP-style)       |
//! | `Control(Detach)`       |  0x14 | emit [`ActiveStageOutput::ClientDetached`]        |
//! | `Persistent Key List`   |  0x2B | silent consume with DoS-cap                       |
//! | `Input` (slow-path)     |  0x1C | silent consume -- handled by Commit 8             |
//! | other `pduType2`        |     ? | error                                             |
//!
//! Fast-path input PDUs and SVC channel data are accepted off the wire
//! but currently dropped; they will be wired up in Commits 8 and 9
//! respectively. The decode is permissive in this commit so the loopback
//! integration test in Commit 10 can already exchange real Windows
//! traffic without misclassifying frames.

use alloc::vec;
use alloc::vec::Vec;

use justrdp_acceptor::AcceptanceResult;
use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_pdu::mcs::{SendDataIndication, SendDataRequest};
use justrdp_pdu::rdp::finalization::{
    ControlAction, ControlPdu, PersistentKeyListPdu, RefreshRectPdu, ShutdownDeniedPdu,
    ShutdownRequestPdu, SuppressOutputPdu,
};
use justrdp_pdu::rdp::headers::{
    ShareControlHeader, ShareControlPduType, ShareDataHeader, ShareDataPduType,
    SHARE_CONTROL_HEADER_SIZE, SHARE_DATA_HEADER_SIZE,
};
use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
use justrdp_pdu::x224::{DataTransfer, DATA_TRANSFER_HEADER_SIZE};

use crate::config::RdpServerConfig;
use crate::error::{ServerError, ServerResult};
use crate::handler::DisplayRect;

/// Maximum number of `PersistentKeyList` PDUs accepted in one session
/// before the stage rejects further entries. Mirrors the DoS cap the
/// acceptor enforces during finalization.
const MAX_PERSISTENT_KEY_LIST_PDUS: u8 = 64;

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
    pub fn process(&mut self, input: &[u8]) -> ServerResult<Vec<ActiveStageOutput>> {
        if input.is_empty() {
            return Err(ServerError::protocol("empty active-stage PDU"));
        }
        match input[0] {
            TPKT_VERSION => self.process_slow_path(input),
            // Fast-path action bits: 0x00 = FASTPATH_INPUT_ACTION_FASTPATH.
            // Anything else with the low two bits == 0 is also fast-path
            // (the upper 6 bits encode num_events / encryption flags).
            // Commit 8 will decode these into trait calls; this commit
            // silently drops them so the loopback test can ignore client
            // input.
            byte if (byte & 0x03) == 0x00 => Ok(Vec::new()),
            _ => Err(ServerError::protocol("unrecognised PDU framing byte")),
        }
    }

    fn process_slow_path(&mut self, input: &[u8]) -> ServerResult<Vec<ActiveStageOutput>> {
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
            self.process_io_channel(sdr.user_data)
        } else if self.channel_ids.iter().any(|(_, id)| *id == sdr.channel_id) {
            // SVC data -- Commit 9 will dispatch to a registered handler.
            // Drop silently in this commit.
            let _ = sdr.channel_id;
            Ok(Vec::new())
        } else {
            Err(ServerError::protocol(
                "SDR channel ID is neither the I/O channel nor any negotiated VC",
            ))
        }
    }

    fn process_io_channel(&mut self, user_data: &[u8]) -> ServerResult<Vec<ActiveStageOutput>> {
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
        self.dispatch_share_data(sd_hdr.pdu_type2, body)
    }

    fn dispatch_share_data(
        &mut self,
        pdu_type2: ShareDataPduType,
        body: &[u8],
    ) -> ServerResult<Vec<ActiveStageOutput>> {
        match pdu_type2 {
            ShareDataPduType::RefreshRect => self.handle_refresh_rect(body),
            ShareDataPduType::SuppressOutput => self.handle_suppress_output(body),
            ShareDataPduType::ShutdownRequest => self.handle_shutdown_request(body),
            ShareDataPduType::Control => self.handle_control(body),
            ShareDataPduType::PersistentKeyList => self.handle_persistent_key_list(body),
            // Slow-path Input is theoretically possible (the spec does
            // not forbid it post-finalization), but real Windows clients
            // always use fast-path input. Drop silently for now -- the
            // input dispatch lands in Commit 8.
            ShareDataPduType::Input => Ok(Vec::new()),
            other => Err(ServerError::protocol_owned(alloc::format!(
                "unexpected ShareData PDU type in active session: {other:?}"
            ))),
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
    use justrdp_acceptor::AcceptanceResult;
    use justrdp_core::EncodeResult;
    use justrdp_pdu::rdp::finalization::InclusiveRect;
    use justrdp_pdu::x224::{NegotiationRequestFlags, NegotiationResponseFlags, SecurityProtocol};

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
        assert!(s.process(&[]).is_err());
    }

    #[test]
    fn unrecognised_first_byte_errors() {
        let mut s = fake_stage();
        // 0x05 -> low bits 0b01, neither TPKT (0x03) nor fast-path (0x00)
        let err = s.process(&[0x05, 0x00, 0x00, 0x00]).unwrap_err();
        let msg = alloc::format!("{err}");
        assert!(msg.contains("framing"), "got: {msg}");
    }

    #[test]
    fn fast_path_input_is_silently_consumed() {
        // Commit 5 explicitly drops fast-path bytes; Commit 8 will
        // replace this branch with proper input-event dispatch.
        let mut s = fake_stage();
        let bytes = [0x00u8, 0x05]; // action=0, length=5 (truncated, but parser doesn't reach it)
        let out = s.process(&bytes).unwrap();
        assert!(out.is_empty());
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
        let out = s.process(&bytes).unwrap();
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
        let out = s.process(&bytes).unwrap();
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
        let out = s.process(&bytes).unwrap();
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
        let out = s.process(&bytes).unwrap();
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
        let out = s.process(&bytes).unwrap();
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
        let out = s.process(&bytes).unwrap();
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
        assert!(s.process(&bytes).is_err());
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
        let out = s.process(&bytes).unwrap();
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
        assert!(s.process(&bytes).is_err());
    }

    #[test]
    fn slow_path_input_dropped_silently() {
        // Real Windows clients use fast-path; the slow-path branch
        // exists for spec completeness. Commit 8 will route both into
        // the InputHandler.
        let mut s = fake_stage();
        // Empty body suffices for the dispatch test.
        let bytes = wrap_client_share_data(&s, ShareDataPduType::Input, &EmptyBody);
        let out = s.process(&bytes).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn unrecognised_share_data_type_errors() {
        let mut s = fake_stage();
        // PlaySound (34 = 0x22) is server→client only; client emitting it
        // is malformed.
        let bytes = wrap_client_share_data(&s, ShareDataPduType::PlaySound, &EmptyBody);
        assert!(s.process(&bytes).is_err());
    }

    #[test]
    fn sdr_with_wrong_initiator_errors() {
        let mut s = fake_stage();
        // Build a synthetic SDR with a bogus initiator.
        let pdu = ShutdownRequestPdu;
        let inner_bytes = wrap_client_share_data(&s, ShareDataPduType::ShutdownRequest, &pdu);
        // Patch the SDR initiator field by re-decoding and re-encoding
        // would be intrusive; instead build the envelope manually with
        // a wrong initiator.
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
        let _ = inner_bytes; // silence unused-variable lint
        assert!(s.process(&buf).is_err());
    }

    #[test]
    fn svc_channel_data_dropped_silently() {
        // Commit 9 will route VC payloads via the SvcHandler trait.
        let mut s = fake_stage();
        // Build a minimal SDR addressed to the rdpsnd VC (0x03EC) that
        // our fake_result() registers.
        let payload = b"hello";
        let sdr = SendDataRequest {
            initiator: s.user_channel_id,
            channel_id: 0x03EC,
            user_data: payload,
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
        let out = s.process(&buf).unwrap();
        assert!(out.is_empty());
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
