#![forbid(unsafe_code)]

//! Server-side clipboard channel processor -- MS-RDPECLIP server role.
//!
//! Mirror of [`crate::CliprdrClient`] for the server direction. Drives
//! the MS-RDPECLIP 3.2 initialization sequence (Server Caps → Monitor
//! Ready → Client Caps → Format List → Format List Response) and
//! delegates clipboard events to an application-supplied
//! [`RdpServerClipboardHandler`].

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_svc::{
    ChannelName, CompressionCondition, SvcMessage, SvcProcessor, SvcResult, SvcServerProcessor,
    CLIPRDR,
};

use crate::backend::{ClipboardError, ClipboardResult, FormatDataResponse, FormatListResponse};
use crate::pdu::{
    ClipboardCapsPdu, ClipboardHeader, ClipboardMsgFlags, ClipboardMsgType,
    FileContentsRequestPdu, FileContentsResponsePdu, FormatDataRequestPdu, FormatDataResponsePdu,
    FormatListPdu, FormatListResponsePdu, GeneralCapabilityFlags, GeneralCapabilitySet,
    LockClipDataPdu, LongFormatName, ShortFormatName, UnlockClipDataPdu, CB_CAPS_VERSION_2,
};

/// Server-side clipboard channel state -- MS-RDPECLIP 3.2 abstract data model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClipboardServerState {
    /// `start()` has not been called yet.
    NotStarted,
    /// Server emitted Caps + Monitor Ready; awaiting any combination of
    /// Client Caps / TempDirectory / first Format List from the client.
    WaitingForInit,
    /// First Format List received and acknowledged; full data exchange
    /// enabled.
    Initialized,
}

/// Application-side clipboard handler invoked by [`ClipboardServer`]
/// when the client drives clipboard events.
///
/// Semantically symmetric to [`crate::CliprdrBackend`] above the
/// initialization sequence -- only the state machine and trait identity
/// differ, so a client backend cannot be accidentally wired into the
/// server processor.
pub trait RdpServerClipboardHandler: Send {
    /// Client advertised new clipboard formats via Format List PDU.
    ///
    /// Return `Ok` to accept (server responds `CB_RESPONSE_OK` in the
    /// Format List Response PDU) or `Fail` to reject.
    fn on_format_list(
        &mut self,
        formats: &[LongFormatName],
    ) -> ClipboardResult<FormatListResponse>;

    /// Client requested clipboard data from the server in `format_id`
    /// via Format Data Request PDU (client pulls from server).
    fn on_format_data_request(
        &mut self,
        format_id: u32,
    ) -> ClipboardResult<FormatDataResponse>;

    /// Client responded to a server-initiated Format Data Request PDU
    /// (server pulled from client). `format_id` carries the format the
    /// server originally asked for, or `None` if the processor cannot
    /// correlate this response with a prior outgoing request.
    fn on_format_data_response(
        &mut self,
        data: &[u8],
        is_success: bool,
        format_id: Option<u32>,
    );

    /// Client requested file contents. Default rejects with an error,
    /// which the server translates into a failure FileContentsResponse.
    fn on_file_contents_request(
        &mut self,
        _request: &FileContentsRequestPdu,
    ) -> ClipboardResult<FileContentsResponsePdu> {
        Err(ClipboardError::Other(String::from(
            "file transfer not supported",
        )))
    }

    /// Client responded with file contents after a server-initiated
    /// request. Default drops the response.
    fn on_file_contents_response(&mut self, _response: &FileContentsResponsePdu) {}

    /// Client emitted a Lock Clipboard Data PDU (CAN_LOCK_CLIPDATA only).
    fn on_lock(&mut self, _clip_data_id: u32) {}

    /// Client emitted an Unlock Clipboard Data PDU.
    fn on_unlock(&mut self, _clip_data_id: u32) {}
}

/// Server-side CLIPRDR SVC channel processor.
///
/// `start()` emits Server Capabilities + Monitor Ready (MS-RDPECLIP 3.2);
/// subsequent `process()` calls handle client PDUs and invoke the
/// application's [`RdpServerClipboardHandler`]. Proactive server-side
/// emits (advertising server clipboard formats or pulling data from the
/// client) use [`ClipboardServer::build_format_list`] and
/// [`ClipboardServer::build_format_data_request`].
pub struct ClipboardServer {
    state: ClipboardServerState,
    handler: Box<dyn RdpServerClipboardHandler>,
    /// Server capability flags advertised in the Caps PDU.
    local_flags: GeneralCapabilityFlags,
    /// Intersection of server and client flags, populated when the
    /// client Caps PDU arrives. Defaults to NONE per MS-RDPECLIP 3.3.1.1
    /// if the client never sends a Caps PDU.
    negotiated_flags: GeneralCapabilityFlags,
    /// Format ID of the most recent outgoing FormatDataRequest sent by
    /// the server; correlates with the eventual FormatDataResponse.
    pending_format_data_request: Option<u32>,
}

impl AsAny for ClipboardServer {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl core::fmt::Debug for ClipboardServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClipboardServer")
            .field("state", &self.state)
            .field("local_flags", &self.local_flags)
            .field("negotiated_flags", &self.negotiated_flags)
            .finish()
    }
}

impl ClipboardServer {
    /// Construct a server processor backed by `handler`.
    pub fn new(handler: Box<dyn RdpServerClipboardHandler>) -> Self {
        Self {
            state: ClipboardServerState::NotStarted,
            handler,
            local_flags: GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
                .union(GeneralCapabilityFlags::STREAM_FILECLIP_ENABLED)
                .union(GeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS)
                .union(GeneralCapabilityFlags::CAN_LOCK_CLIPDATA)
                .union(GeneralCapabilityFlags::HUGE_FILE_SUPPORT_ENABLED),
            negotiated_flags: GeneralCapabilityFlags::NONE,
            pending_format_data_request: None,
        }
    }

    /// Override the capability flags the server advertises.
    pub fn with_flags(mut self, flags: GeneralCapabilityFlags) -> Self {
        self.local_flags = flags;
        self
    }

    /// Whether long format names were negotiated with the client.
    pub fn use_long_format_names(&self) -> bool {
        self.negotiated_flags
            .contains(GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES)
    }

    /// Currently negotiated capability flags (NONE until the client
    /// Caps PDU arrives).
    pub fn negotiated_flags(&self) -> GeneralCapabilityFlags {
        self.negotiated_flags
    }

    fn encode_pdu<T: Encode>(pdu: &T) -> SvcResult<SvcMessage> {
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor)?;
        Ok(SvcMessage::new(buf))
    }

    fn encode_format_list(pdu: &FormatListPdu) -> SvcResult<SvcMessage> {
        let mut buf = alloc::vec![0u8; pdu.full_size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode_full(&mut cursor)?;
        Ok(SvcMessage::new(buf))
    }

    /// Build the initial server burst per MS-RDPECLIP 3.2:
    /// Server Capabilities PDU, then Monitor Ready PDU.
    fn build_initial_burst(&self) -> SvcResult<Vec<SvcMessage>> {
        let caps = ClipboardCapsPdu::new(GeneralCapabilitySet::new(
            CB_CAPS_VERSION_2,
            self.local_flags,
        ));
        let ready = ClipboardHeader::new(
            ClipboardMsgType::MonitorReady,
            ClipboardMsgFlags::NONE,
            0,
        );
        Ok(alloc::vec![
            Self::encode_pdu(&caps)?,
            Self::encode_pdu(&ready)?,
        ])
    }

    fn handle_pdu(
        &mut self,
        header: &ClipboardHeader,
        body: &mut ReadCursor<'_>,
    ) -> SvcResult<Vec<SvcMessage>> {
        // Before the first Format List completes initialization, only
        // the init-phase PDUs (Caps / TempDirectory / FormatList) do
        // meaningful work. MS-RDPECLIP 3.1.5.1: unexpected PDUs SHOULD
        // be ignored, not errored.
        if self.state != ClipboardServerState::Initialized {
            match header.msg_type {
                ClipboardMsgType::ClipCaps
                | ClipboardMsgType::TempDirectory
                | ClipboardMsgType::FormatList => {}
                _ => return Ok(Vec::new()),
            }
        }

        match header.msg_type {
            ClipboardMsgType::MonitorReady => {
                // Server-only PDU. If received (wrong direction), ignore.
                Ok(Vec::new())
            }

            ClipboardMsgType::ClipCaps => {
                let caps = ClipboardCapsPdu::decode(body)?;
                let remote_flags = caps.general.general_flags;
                self.negotiated_flags = GeneralCapabilityFlags::from_bits(
                    self.local_flags.bits() & remote_flags.bits(),
                );
                Ok(Vec::new())
            }

            ClipboardMsgType::TempDirectory => {
                // Informational: the path the client wants the server
                // to use for file-stream temp storage. Server has no
                // local clipboard area to honour this, so discard.
                Ok(Vec::new())
            }

            ClipboardMsgType::FormatList => {
                let pdu = FormatListPdu::decode_body(
                    body,
                    self.use_long_format_names(),
                    header.msg_flags,
                    header.data_len,
                )?;

                let formats = match &pdu {
                    FormatListPdu::Long(entries) => entries.clone(),
                    FormatListPdu::Short { entries, .. } => entries
                        .iter()
                        .map(|e| LongFormatName::new(e.format_id, String::new()))
                        .collect(),
                };

                // First Format List completes initialization
                // (MS-RDPECLIP 3.2: after receiving Format List the
                // server responds and the data-exchange phase begins).
                if self.state != ClipboardServerState::Initialized {
                    self.state = ClipboardServerState::Initialized;
                }

                // Handler errors are degraded to Fail -- the server
                // MUST respond with a Format List Response PDU in
                // every case (MS-RDPECLIP 3.1.5.2.3).
                let response = self
                    .handler
                    .on_format_list(&formats)
                    .unwrap_or(FormatListResponse::Fail);

                let resp_pdu = match response {
                    FormatListResponse::Ok => FormatListResponsePdu::ok(),
                    FormatListResponse::Fail => FormatListResponsePdu::fail(),
                };
                Ok(alloc::vec![Self::encode_pdu(&resp_pdu)?])
            }

            ClipboardMsgType::FormatListResponse => {
                // Client acknowledging a server-emitted Format List.
                // No recovery action on FAIL (subsequent data requests
                // for that list will simply fail); silently accept.
                Ok(Vec::new())
            }

            ClipboardMsgType::FormatDataRequest => {
                let request = FormatDataRequestPdu::decode_body(body)?;
                let response = self
                    .handler
                    .on_format_data_request(request.requested_format_id)
                    .unwrap_or(FormatDataResponse::Fail);

                let resp_pdu = match response {
                    FormatDataResponse::Ok(data) => FormatDataResponsePdu::Ok(data),
                    FormatDataResponse::Fail => FormatDataResponsePdu::Fail,
                };
                Ok(alloc::vec![Self::encode_pdu(&resp_pdu)?])
            }

            ClipboardMsgType::FormatDataResponse => {
                let resp = FormatDataResponsePdu::decode_body(
                    body,
                    header.msg_flags,
                    header.data_len,
                )?;
                let (data, is_success) = match &resp {
                    FormatDataResponsePdu::Ok(d) => (d.as_slice(), true),
                    FormatDataResponsePdu::Fail => (&[][..], false),
                };
                let format_id = self.pending_format_data_request.take();
                self.handler.on_format_data_response(data, is_success, format_id);
                Ok(Vec::new())
            }

            ClipboardMsgType::FileContentsRequest => {
                let request = FileContentsRequestPdu::decode_body(body, header.data_len)?;
                let response = self.handler.on_file_contents_request(&request);

                let resp_pdu = match response {
                    Ok(resp) => resp,
                    Err(_) => FileContentsResponsePdu::fail(request.stream_id),
                };
                Ok(alloc::vec![Self::encode_pdu(&resp_pdu)?])
            }

            ClipboardMsgType::FileContentsResponse => {
                let response = FileContentsResponsePdu::decode_body(
                    body,
                    header.msg_flags,
                    header.data_len,
                )?;
                self.handler.on_file_contents_response(&response);
                Ok(Vec::new())
            }

            ClipboardMsgType::LockClipData => {
                let lock = LockClipDataPdu::decode_body(body)?;
                self.handler.on_lock(lock.clip_data_id);
                Ok(Vec::new())
            }

            ClipboardMsgType::UnlockClipData => {
                let unlock = UnlockClipDataPdu::decode_body(body)?;
                self.handler.on_unlock(unlock.clip_data_id);
                Ok(Vec::new())
            }
        }
    }
}

// Outbound proactive emit helpers.
impl ClipboardServer {
    /// Build a Format List PDU advertising the server's clipboard
    /// formats. Call when the server-side clipboard content changes.
    /// Respects the negotiated `USE_LONG_FORMAT_NAMES` flag.
    pub fn build_format_list(&self, formats: &[LongFormatName]) -> SvcResult<SvcMessage> {
        let pdu = if self.use_long_format_names() {
            FormatListPdu::Long(formats.to_vec())
        } else {
            let entries = formats
                .iter()
                .map(|f| ShortFormatName::new(f.format_id))
                .collect();
            FormatListPdu::Short {
                ascii_names: false,
                entries,
            }
        };
        Self::encode_format_list(&pdu)
    }

    /// Build a Format Data Request PDU asking the client for clipboard
    /// data in `format_id`. The response will be dispatched to
    /// [`RdpServerClipboardHandler::on_format_data_response`].
    pub fn build_format_data_request(&mut self, format_id: u32) -> SvcResult<SvcMessage> {
        self.pending_format_data_request = Some(format_id);
        let pdu = FormatDataRequestPdu::new(format_id);
        Self::encode_pdu(&pdu)
    }

    /// Build a Lock Clipboard Data PDU (CAN_LOCK_CLIPDATA only).
    pub fn build_lock(&self, clip_data_id: u32) -> SvcResult<SvcMessage> {
        let pdu = LockClipDataPdu::new(clip_data_id);
        Self::encode_pdu(&pdu)
    }

    /// Build an Unlock Clipboard Data PDU.
    pub fn build_unlock(&self, clip_data_id: u32) -> SvcResult<SvcMessage> {
        let pdu = UnlockClipDataPdu::new(clip_data_id);
        Self::encode_pdu(&pdu)
    }
}

impl SvcProcessor for ClipboardServer {
    fn channel_name(&self) -> ChannelName {
        CLIPRDR
    }

    fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
        if self.state != ClipboardServerState::NotStarted {
            return Ok(Vec::new());
        }
        self.state = ClipboardServerState::WaitingForInit;
        self.build_initial_burst()
    }

    fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
        // MS-RDPECLIP 3.1.5.1: an unrecognized msgType SHOULD be ignored
        // (not errored). Peek the first 2 bytes so an unknown type drops
        // silently without surfacing a DecodeError to the caller.
        // dataLen / truncation errors still propagate -- those warrant
        // a connection drop per the same section.
        if payload.len() >= 2 {
            let raw_type = u16::from_le_bytes([payload[0], payload[1]]);
            if ClipboardMsgType::from_u16(raw_type).is_none() {
                return Ok(Vec::new());
            }
        }
        let mut cursor = ReadCursor::new(payload);
        let header = ClipboardHeader::decode(&mut cursor)?;
        self.handle_pdu(&header, &mut cursor)
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }
}

impl SvcServerProcessor for ClipboardServer {}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use std::sync::{Arc, Mutex};

    use crate::pdu::{
        ClipboardCapsPdu, ClipboardHeader, ClipboardMsgFlags, ClipboardMsgType,
        FormatDataRequestPdu, FormatDataResponsePdu, FormatListPdu, FormatListResponsePdu,
        GeneralCapabilityFlags, GeneralCapabilitySet, ShortFormatName, CB_CAPS_VERSION_2,
    };

    /// Shared state observed by the test after handler calls. Wrapped
    /// in `Arc<Mutex<_>>` because `RdpServerClipboardHandler: Send`
    /// propagates the bound through the handler field, so a non-`Send`
    /// container (`Rc<RefCell<_>>`) would fail to satisfy the trait.
    #[derive(Default)]
    struct HandlerState {
        format_list_calls: Vec<Vec<LongFormatName>>,
        format_data_request_id: Option<u32>,
        format_data_response_data: Option<Vec<u8>>,
        format_data_response_format_id: Option<Option<u32>>,
        format_data_response_is_success: Option<bool>,
        lock_ids: Vec<u32>,
        unlock_ids: Vec<u32>,
    }

    /// Test handler that forwards every call into a shared
    /// `HandlerState`, letting the test observe what `ClipboardServer`
    /// dispatched to the application.
    struct MockHandler {
        state: Arc<Mutex<HandlerState>>,
        format_list_response: FormatListResponse,
        format_data_request_response: FormatDataResponse,
    }

    impl MockHandler {
        fn new() -> (Self, Arc<Mutex<HandlerState>>) {
            let state = Arc::new(Mutex::new(HandlerState::default()));
            (
                Self {
                    state: state.clone(),
                    format_list_response: FormatListResponse::Ok,
                    format_data_request_response: FormatDataResponse::Ok(vec![0x42]),
                },
                state,
            )
        }
    }

    impl RdpServerClipboardHandler for MockHandler {
        fn on_format_list(
            &mut self,
            formats: &[LongFormatName],
        ) -> ClipboardResult<FormatListResponse> {
            self.state.lock().unwrap().format_list_calls.push(formats.to_vec());
            Ok(self.format_list_response)
        }

        fn on_format_data_request(
            &mut self,
            format_id: u32,
        ) -> ClipboardResult<FormatDataResponse> {
            self.state.lock().unwrap().format_data_request_id = Some(format_id);
            match &self.format_data_request_response {
                FormatDataResponse::Ok(data) => Ok(FormatDataResponse::Ok(data.clone())),
                FormatDataResponse::Fail => Ok(FormatDataResponse::Fail),
            }
        }

        fn on_format_data_response(
            &mut self,
            data: &[u8],
            is_success: bool,
            format_id: Option<u32>,
        ) {
            let mut s = self.state.lock().unwrap();
            s.format_data_response_data = Some(data.to_vec());
            s.format_data_response_is_success = Some(is_success);
            s.format_data_response_format_id = Some(format_id);
        }

        fn on_lock(&mut self, clip_data_id: u32) {
            self.state.lock().unwrap().lock_ids.push(clip_data_id);
        }

        fn on_unlock(&mut self, clip_data_id: u32) {
            self.state.lock().unwrap().unlock_ids.push(clip_data_id);
        }
    }

    fn new_server() -> (ClipboardServer, Arc<Mutex<HandlerState>>) {
        let (handler, state) = MockHandler::new();
        (ClipboardServer::new(Box::new(handler)), state)
    }

    fn encode_bytes<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        buf
    }

    fn encode_format_list_bytes(pdu: &FormatListPdu) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.full_size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode_full(&mut cursor).unwrap();
        buf
    }

    fn client_caps_bytes(flags: GeneralCapabilityFlags) -> Vec<u8> {
        let caps = ClipboardCapsPdu::new(GeneralCapabilitySet::new(CB_CAPS_VERSION_2, flags));
        encode_bytes(&caps)
    }

    fn long_format_list_bytes(entries: Vec<LongFormatName>) -> Vec<u8> {
        encode_format_list_bytes(&FormatListPdu::Long(entries))
    }

    fn short_format_list_bytes(ids: &[u32]) -> Vec<u8> {
        encode_format_list_bytes(&FormatListPdu::Short {
            ascii_names: false,
            entries: ids.iter().map(|&id| ShortFormatName::new(id)).collect(),
        })
    }

    fn format_data_request_bytes(format_id: u32) -> Vec<u8> {
        encode_bytes(&FormatDataRequestPdu::new(format_id))
    }

    fn format_data_response_ok_bytes(data: Vec<u8>) -> Vec<u8> {
        encode_bytes(&FormatDataResponsePdu::Ok(data))
    }

    fn format_data_response_fail_bytes() -> Vec<u8> {
        encode_bytes(&FormatDataResponsePdu::Fail)
    }

    fn format_list_response_bytes(accepted: bool) -> Vec<u8> {
        let pdu = if accepted {
            FormatListResponsePdu::ok()
        } else {
            FormatListResponsePdu::fail()
        };
        encode_bytes(&pdu)
    }

    /// Decode a ClipboardHeader from `msg.data`.
    fn decode_header(msg: &SvcMessage) -> ClipboardHeader {
        let mut cursor = ReadCursor::new(&msg.data);
        ClipboardHeader::decode(&mut cursor).unwrap()
    }

    #[test]
    fn start_emits_caps_then_monitor_ready() {
        // MS-RDPECLIP 3.2: server MUST send Caps before Monitor Ready.
        let (mut server, _state) = new_server();
        let msgs = server.start().unwrap();
        assert_eq!(msgs.len(), 2, "expected Caps + MonitorReady");

        let h0 = decode_header(&msgs[0]);
        assert_eq!(h0.msg_type, ClipboardMsgType::ClipCaps);
        let h1 = decode_header(&msgs[1]);
        assert_eq!(h1.msg_type, ClipboardMsgType::MonitorReady);
        assert_eq!(h1.data_len, 0);
        assert_eq!(h1.msg_flags, ClipboardMsgFlags::NONE);
    }

    #[test]
    fn start_is_idempotent() {
        let (mut server, _state) = new_server();
        let first = server.start().unwrap();
        assert_eq!(first.len(), 2);
        let second = server.start().unwrap();
        assert!(second.is_empty(), "second start() must be a no-op");
    }

    #[test]
    fn capability_flag_intersection() {
        let (handler, _state) = MockHandler::new();
        let mut server = ClipboardServer::new(Box::new(handler)).with_flags(
            GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
                .union(GeneralCapabilityFlags::STREAM_FILECLIP_ENABLED),
        );
        server.start().unwrap();

        // Client advertises ULFN only.
        let resp = server
            .process(&client_caps_bytes(GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES))
            .unwrap();
        assert!(resp.is_empty(), "no response to client Caps");

        assert!(server.use_long_format_names());
        assert!(!server
            .negotiated_flags()
            .contains(GeneralCapabilityFlags::STREAM_FILECLIP_ENABLED));
    }

    #[test]
    fn client_caps_then_format_list_initializes() {
        let (mut server, _state) = new_server();
        server.start().unwrap();
        server
            .process(&client_caps_bytes(GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES))
            .unwrap();

        // Long-format negotiated → client sends Long Format List.
        let entries = vec![LongFormatName::new(0x000D, String::new())]; // CF_UNICODETEXT
        let msgs = server.process(&long_format_list_bytes(entries)).unwrap();

        assert_eq!(msgs.len(), 1, "expected FormatListResponse");
        let h = decode_header(&msgs[0]);
        assert_eq!(h.msg_type, ClipboardMsgType::FormatListResponse);
        assert!(h.msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_OK));
    }

    #[test]
    fn client_skips_caps_falls_back_to_short_format_list() {
        // MS-RDPECLIP 3.3.1.1: if no Caps PDU ever arrives, flags default to 0.
        // Short Format Name variant MUST then be used.
        let (mut server, _state) = new_server();
        server.start().unwrap();
        assert_eq!(server.negotiated_flags(), GeneralCapabilityFlags::NONE);

        let msgs = server.process(&short_format_list_bytes(&[0x0001])).unwrap(); // CF_TEXT
        assert_eq!(msgs.len(), 1);
        let h = decode_header(&msgs[0]);
        assert_eq!(h.msg_type, ClipboardMsgType::FormatListResponse);
        assert!(h.msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_OK));
    }

    #[test]
    fn empty_format_list_accepted() {
        let (mut server, _state) = new_server();
        server.start().unwrap();
        let msgs = server.process(&long_format_list_bytes(vec![])).unwrap();
        assert_eq!(msgs.len(), 1);
        let h = decode_header(&msgs[0]);
        assert!(h.msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_OK));
    }

    #[test]
    fn data_exchange_before_initialization_dropped() {
        // FormatDataRequest before the first Format List MUST NOT produce a response.
        let (mut server, _state) = new_server();
        server.start().unwrap();
        let msgs = server.process(&format_data_request_bytes(0x000D)).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn format_data_request_from_client_returns_ok() {
        let (mut server, _state) = new_server();
        server.start().unwrap();
        server
            .process(&long_format_list_bytes(vec![LongFormatName::new(0x000D, String::new())]))
            .unwrap(); // initialize

        let msgs = server.process(&format_data_request_bytes(0x000D)).unwrap();
        assert_eq!(msgs.len(), 1);
        let h = decode_header(&msgs[0]);
        assert_eq!(h.msg_type, ClipboardMsgType::FormatDataResponse);
        assert!(h.msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_OK));
        assert_eq!(h.data_len, 1); // MockHandler returns [0x42]
    }

    #[test]
    fn format_data_request_handler_fail_produces_fail_response() {
        struct FailHandler;
        impl RdpServerClipboardHandler for FailHandler {
            fn on_format_list(
                &mut self,
                _f: &[LongFormatName],
            ) -> ClipboardResult<FormatListResponse> {
                Ok(FormatListResponse::Ok)
            }
            fn on_format_data_request(
                &mut self,
                _id: u32,
            ) -> ClipboardResult<FormatDataResponse> {
                Ok(FormatDataResponse::Fail)
            }
            fn on_format_data_response(
                &mut self,
                _d: &[u8],
                _ok: bool,
                _f: Option<u32>,
            ) {
            }
        }

        let mut server = ClipboardServer::new(Box::new(FailHandler));
        server.start().unwrap();
        server.process(&long_format_list_bytes(vec![])).unwrap();
        let msgs = server.process(&format_data_request_bytes(0x000D)).unwrap();
        assert_eq!(msgs.len(), 1);
        let h = decode_header(&msgs[0]);
        assert!(h.msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_FAIL));
        assert_eq!(h.data_len, 0);
    }

    #[test]
    fn server_build_format_list_long_variant() {
        let (mut server, _state) = new_server();
        server.start().unwrap();
        server
            .process(&client_caps_bytes(GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES))
            .unwrap();

        let formats = vec![LongFormatName::new(0x000D, String::from("UnicodeText"))];
        let msg = server.build_format_list(&formats).unwrap();
        let h = decode_header(&msg);
        assert_eq!(h.msg_type, ClipboardMsgType::FormatList);
        // Long variant carries UTF-16LE bytes.
        let mut cursor = ReadCursor::new(&msg.data);
        let _ = ClipboardHeader::decode(&mut cursor).unwrap();
        let decoded = FormatListPdu::decode_body(
            &mut cursor,
            true,
            h.msg_flags,
            h.data_len,
        )
        .unwrap();
        assert!(matches!(decoded, FormatListPdu::Long(_)));
    }

    #[test]
    fn server_build_format_list_short_variant_when_no_long_negotiated() {
        let (mut server, _state) = new_server();
        server.start().unwrap();
        // No client Caps → negotiated = NONE → Short variant.
        let formats = vec![LongFormatName::new(0x0001, String::new())];
        let msg = server.build_format_list(&formats).unwrap();
        let h = decode_header(&msg);
        let mut cursor = ReadCursor::new(&msg.data);
        let _ = ClipboardHeader::decode(&mut cursor).unwrap();
        let decoded = FormatListPdu::decode_body(
            &mut cursor,
            false,
            h.msg_flags,
            h.data_len,
        )
        .unwrap();
        match decoded {
            FormatListPdu::Short { entries, .. } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].format_id, 0x0001);
            }
            _ => panic!("expected Short variant"),
        }
    }

    #[test]
    fn server_pulled_data_dispatches_to_handler_with_format_id() {
        let (mut server, state) = new_server();
        server.start().unwrap();
        server.process(&long_format_list_bytes(vec![])).unwrap();

        // Server requests data from client; stores pending format_id.
        let _req = server.build_format_data_request(0x000D).unwrap();

        // Client responds with 5 bytes "Hello".
        let hello = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
        let resp = server.process(&format_data_response_ok_bytes(hello.clone())).unwrap();
        assert!(resp.is_empty(), "server produces no outbound on data response");

        let s = state.lock().unwrap();
        assert_eq!(s.format_data_response_data.as_deref(), Some(&hello[..]));
        assert_eq!(s.format_data_response_is_success, Some(true));
        assert_eq!(s.format_data_response_format_id, Some(Some(0x000D)));
    }

    #[test]
    fn format_data_response_without_pending_request_passes_none() {
        let (mut server, state) = new_server();
        server.start().unwrap();
        server.process(&long_format_list_bytes(vec![])).unwrap();

        // No build_format_data_request() — incoming response cannot be correlated.
        let resp = server.process(&format_data_response_ok_bytes(vec![0x01])).unwrap();
        assert!(resp.is_empty());

        assert_eq!(state.lock().unwrap().format_data_response_format_id, Some(None));
    }

    #[test]
    fn format_data_response_fail_dispatched() {
        let (mut server, state) = new_server();
        server.start().unwrap();
        server.process(&long_format_list_bytes(vec![])).unwrap();
        let _ = server.build_format_data_request(0x0001).unwrap();

        server.process(&format_data_response_fail_bytes()).unwrap();
        let s = state.lock().unwrap();
        assert_eq!(s.format_data_response_is_success, Some(false));
        assert_eq!(s.format_data_response_format_id, Some(Some(0x0001)));
    }

    #[test]
    fn format_list_response_from_client_does_not_crash() {
        let (mut server, _state) = new_server();
        server.start().unwrap();
        server.process(&long_format_list_bytes(vec![])).unwrap();

        let resp = server.process(&format_list_response_bytes(false)).unwrap();
        assert!(resp.is_empty());
        let resp = server.process(&format_list_response_bytes(true)).unwrap();
        assert!(resp.is_empty());
    }

    #[test]
    fn duplicate_format_list_updates_handler_call_log() {
        let (mut server, state) = new_server();
        server.start().unwrap();
        // Negotiate long format names so the Long Format List bytes parse.
        server
            .process(&client_caps_bytes(GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES))
            .unwrap();

        server
            .process(&long_format_list_bytes(vec![LongFormatName::new(
                0x0001,
                String::new(),
            )]))
            .unwrap();
        server
            .process(&long_format_list_bytes(vec![
                LongFormatName::new(0x000D, String::new()),
                LongFormatName::new(0x000F, String::new()),
            ]))
            .unwrap();

        let s = state.lock().unwrap();
        assert_eq!(s.format_list_calls.len(), 2);
        assert_eq!(s.format_list_calls[0].len(), 1);
        assert_eq!(s.format_list_calls[1].len(), 2);
    }

    #[test]
    fn lock_and_unlock_dispatched_to_handler() {
        let (mut server, state) = new_server();
        server.start().unwrap();
        server.process(&long_format_list_bytes(vec![])).unwrap();

        let lock = LockClipDataPdu::new(0xABCD);
        let unlock = UnlockClipDataPdu::new(0xABCD);
        server.process(&encode_bytes(&lock)).unwrap();
        server.process(&encode_bytes(&unlock)).unwrap();

        let s = state.lock().unwrap();
        assert_eq!(s.lock_ids, vec![0xABCD]);
        assert_eq!(s.unlock_ids, vec![0xABCD]);
    }

    #[test]
    fn unknown_msg_type_silently_dropped() {
        // MS-RDPECLIP 3.1.5.1: unknown msgType SHOULD be ignored, not errored.
        let (mut server, _state) = new_server();
        server.start().unwrap();
        // msgType=0xFFFF (undefined), msgFlags=0, dataLen=0.
        let bogus: Vec<u8> = vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let resp = server.process(&bogus).unwrap();
        assert!(resp.is_empty(), "unknown msgType must produce Ok(empty)");
    }

    #[test]
    fn caps_pdu_test_vector_intersection() {
        // MS-RDPECLIP 4.1.1 spec test vector (server Caps with flags=0x0E)
        // is reused here as the client-direction input.
        let bytes: Vec<u8> = vec![
            0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // header
            0x01, 0x00, 0x00, 0x00, // cCapabilitiesSets=1, pad1=0
            0x01, 0x00, 0x0C, 0x00, // type=GENERAL, length=12
            0x02, 0x00, 0x00, 0x00, // version=2
            0x0E, 0x00, 0x00, 0x00, // flags=0x0E
        ];
        let (mut server, _state) = new_server();
        server.start().unwrap();
        server.process(&bytes).unwrap();
        // local_flags default includes ULFN+STREAM_FILECLIP+NO_FILE_PATHS+CAN_LOCK+HUGE_FILE
        // client_flags 0x0E = ULFN(0x02) | STREAM_FILECLIP(0x04) | NO_FILE_PATHS(0x08)
        // intersection = 0x0E
        assert_eq!(server.negotiated_flags().bits(), 0x0E);
    }
}
