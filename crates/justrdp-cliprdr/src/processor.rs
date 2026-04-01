#![forbid(unsafe_code)]

//! Clipboard channel processor -- SVC integration.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_svc::{
    ChannelName, CompressionCondition, SvcClientProcessor, SvcMessage, SvcProcessor, SvcResult,
    CLIPRDR,
};

use crate::backend::{CliprdrBackend, FormatDataResponse, FormatListResponse};
use crate::pdu::{
    ClipboardCapsPdu, ClipboardHeader, ClipboardMsgType,
    FileContentsRequestPdu, FileContentsResponsePdu, FormatDataRequestPdu,
    FormatDataResponsePdu, FormatListPdu, FormatListResponsePdu, GeneralCapabilityFlags,
    GeneralCapabilitySet, LockClipDataPdu, LongFormatName, ShortFormatName, TempDirectoryPdu,
    UnlockClipDataPdu, CB_CAPS_VERSION_2,
};

/// Client-side clipboard channel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliprdrState {
    /// Waiting for server capabilities.
    WaitingForServerCaps,
    /// Received server caps, waiting for monitor ready.
    WaitingForMonitorReady,
    /// Initialization complete, ready for data exchange.
    Initialized,
}

/// Client-side clipboard channel processor.
///
/// Implements [`SvcProcessor`] to handle the CLIPRDR virtual channel.
pub struct CliprdrClient {
    state: CliprdrState,
    backend: Box<dyn CliprdrBackend>,
    /// Our capability flags to advertise.
    local_flags: GeneralCapabilityFlags,
    /// Negotiated capability flags (intersection of local and remote).
    negotiated_flags: GeneralCapabilityFlags,
    /// Optional temporary directory path.
    temp_dir: Option<String>,
}

impl AsAny for CliprdrClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl core::fmt::Debug for CliprdrClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CliprdrClient")
            .field("state", &self.state)
            .field("local_flags", &self.local_flags)
            .field("negotiated_flags", &self.negotiated_flags)
            .finish()
    }
}

impl CliprdrClient {
    /// Create a new clipboard client processor.
    pub fn new(backend: Box<dyn CliprdrBackend>) -> Self {
        Self {
            state: CliprdrState::WaitingForServerCaps,
            backend,
            local_flags: GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
                .union(GeneralCapabilityFlags::STREAM_FILECLIP_ENABLED)
                .union(GeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS)
                .union(GeneralCapabilityFlags::CAN_LOCK_CLIPDATA)
                .union(GeneralCapabilityFlags::HUGE_FILE_SUPPORT_ENABLED),
            negotiated_flags: GeneralCapabilityFlags::NONE,
            temp_dir: None,
        }
    }

    /// Set the temporary directory path.
    pub fn with_temp_dir(mut self, path: String) -> Self {
        self.temp_dir = Some(path);
        self
    }

    /// Set the local capability flags.
    pub fn with_flags(mut self, flags: GeneralCapabilityFlags) -> Self {
        self.local_flags = flags;
        self
    }

    /// Whether long format names are negotiated.
    pub fn use_long_format_names(&self) -> bool {
        self.negotiated_flags
            .contains(GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES)
    }

    /// Encode a PDU into an SvcMessage.
    fn encode_pdu<T: Encode>(pdu: &T) -> SvcResult<SvcMessage> {
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor)?;
        Ok(SvcMessage::new(buf))
    }

    /// Build the client's initial messages (caps + optional temp dir + empty format list).
    ///
    /// Per MS-RDPECLIP 1.3.2.1, the client MUST send a Format List PDU as part
    /// of the initialization sequence after capabilities and optional temp dir.
    fn build_init_response(&self) -> SvcResult<Vec<SvcMessage>> {
        let mut messages = Vec::new();

        // Send our capabilities.
        let caps = ClipboardCapsPdu::new(GeneralCapabilitySet::new(
            CB_CAPS_VERSION_2,
            self.local_flags,
        ));
        messages.push(Self::encode_pdu(&caps)?);

        // Send temporary directory if set.
        if let Some(ref path) = self.temp_dir {
            let temp = TempDirectoryPdu::new(path.clone());
            messages.push(Self::encode_pdu(&temp)?);
        }

        // Send an empty format list to complete initialization.
        // MS-RDPECLIP 1.3.2.1: client MUST send Format List after caps.
        let format_list = self.build_format_list_pdu(&[])?;
        messages.push(format_list);

        Ok(messages)
    }

    /// Handle a received clipboard PDU.
    fn handle_pdu(
        &mut self,
        header: &ClipboardHeader,
        body: &mut ReadCursor<'_>,
    ) -> SvcResult<Vec<SvcMessage>> {
        match header.msg_type {
            ClipboardMsgType::ClipCaps => {
                let caps = ClipboardCapsPdu::decode(body)?;
                let remote_flags = caps.general.general_flags;
                // Negotiate: intersection of local and remote flags.
                self.negotiated_flags = GeneralCapabilityFlags::from_bits(
                    self.local_flags.bits() & remote_flags.bits(),
                );

                if self.state == CliprdrState::WaitingForServerCaps {
                    self.state = CliprdrState::WaitingForMonitorReady;
                }
                Ok(Vec::new())
            }

            ClipboardMsgType::MonitorReady => {
                self.state = CliprdrState::Initialized;
                // Send our caps + temp dir. Format list will be sent by
                // the application via send_format_list().
                self.build_init_response()
            }

            ClipboardMsgType::FormatList => {
                let pdu = FormatListPdu::decode_body(
                    body,
                    self.use_long_format_names(),
                    header.msg_flags,
                    header.data_len,
                )?;

                // Convert to uniform LongFormatName representation for the backend.
                let formats = match &pdu {
                    FormatListPdu::Long(entries) => entries.clone(),
                    FormatListPdu::Short { entries, .. } => entries
                        .iter()
                        .map(|e| LongFormatName::new(e.format_id, String::new()))
                        .collect(),
                };

                let response = self
                    .backend
                    .on_format_list(&formats)
                    .unwrap_or(FormatListResponse::Fail);

                let resp_pdu = match response {
                    FormatListResponse::Ok => FormatListResponsePdu::ok(),
                    FormatListResponse::Fail => FormatListResponsePdu::fail(),
                };
                Ok(alloc::vec![Self::encode_pdu(&resp_pdu)?])
            }

            ClipboardMsgType::FormatListResponse => {
                // Acknowledgement from server for our format list. Nothing to do.
                Ok(Vec::new())
            }

            ClipboardMsgType::FormatDataRequest => {
                let request = FormatDataRequestPdu::decode_body(body)?;
                let response = self
                    .backend
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
                self.backend.on_format_data_response(data, is_success);
                Ok(Vec::new())
            }

            ClipboardMsgType::FileContentsRequest => {
                let request = FileContentsRequestPdu::decode_body(body, header.data_len)?;
                let response = self.backend.on_file_contents_request(&request);

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
                self.backend.on_file_contents_response(&response);
                Ok(Vec::new())
            }

            ClipboardMsgType::LockClipData => {
                let lock = LockClipDataPdu::decode_body(body)?;
                self.backend.on_lock(lock.clip_data_id);
                Ok(Vec::new())
            }

            ClipboardMsgType::UnlockClipData => {
                let unlock = UnlockClipDataPdu::decode_body(body)?;
                self.backend.on_unlock(unlock.clip_data_id);
                Ok(Vec::new())
            }

            ClipboardMsgType::TempDirectory => {
                // Server should not send this; ignore.
                Ok(Vec::new())
            }
        }
    }
}

impl SvcProcessor for CliprdrClient {
    fn channel_name(&self) -> ChannelName {
        CLIPRDR
    }

    fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
        // Client waits for server to send capabilities first.
        Ok(Vec::new())
    }

    fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
        let mut cursor = ReadCursor::new(payload);
        let header = ClipboardHeader::decode(&mut cursor)?;
        self.handle_pdu(&header, &mut cursor)
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }
}

impl SvcClientProcessor for CliprdrClient {}

// Public API for sending clipboard data proactively.
impl CliprdrClient {
    /// Build a format list message to send to the server.
    ///
    /// Call this when the local clipboard content changes.
    /// Respects the negotiated format name length variant.
    pub fn build_format_list(&self, formats: &[LongFormatName]) -> SvcResult<SvcMessage> {
        self.build_format_list_pdu(formats)
    }

    /// Internal: build a format list SvcMessage respecting negotiated flags.
    ///
    /// MS-RDPECLIP 2.2.3.1: If CB_USE_LONG_FORMAT_NAMES is set by both sides,
    /// use Long Format Name variant; otherwise use Short Format Name variant.
    fn build_format_list_pdu(&self, formats: &[LongFormatName]) -> SvcResult<SvcMessage> {
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
        Self::encode_pdu_with_header(&pdu)
    }

    /// Build a format data request message.
    pub fn build_format_data_request(&self, format_id: u32) -> SvcResult<SvcMessage> {
        let pdu = FormatDataRequestPdu::new(format_id);
        Self::encode_pdu(&pdu)
    }

    /// Build a lock clipboard data message.
    pub fn build_lock(&self, clip_data_id: u32) -> SvcResult<SvcMessage> {
        let pdu = LockClipDataPdu::new(clip_data_id);
        Self::encode_pdu(&pdu)
    }

    /// Build an unlock clipboard data message.
    pub fn build_unlock(&self, clip_data_id: u32) -> SvcResult<SvcMessage> {
        let pdu = UnlockClipDataPdu::new(clip_data_id);
        Self::encode_pdu(&pdu)
    }

    /// Build a file contents request (SIZE) message.
    pub fn build_file_size_request(
        &self,
        stream_id: u32,
        lindex: i32,
    ) -> SvcResult<SvcMessage> {
        let pdu = FileContentsRequestPdu::size_request(stream_id, lindex);
        Self::encode_pdu(&pdu)
    }

    /// Build a file contents request (RANGE) message.
    pub fn build_file_range_request(
        &self,
        stream_id: u32,
        lindex: i32,
        offset: u64,
        cb_requested: u32,
    ) -> SvcResult<SvcMessage> {
        let pdu = FileContentsRequestPdu::range_request(stream_id, lindex, offset, cb_requested);
        Self::encode_pdu(&pdu)
    }

    /// Encode a format list PDU with its header.
    fn encode_pdu_with_header(pdu: &FormatListPdu) -> SvcResult<SvcMessage> {
        let mut buf = alloc::vec![0u8; pdu.full_size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode_full(&mut cursor)?;
        Ok(SvcMessage::new(buf))
    }
}
