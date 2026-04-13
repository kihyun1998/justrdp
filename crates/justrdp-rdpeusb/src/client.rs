#![forbid(unsafe_code)]

//! URBDRC DVC client — MS-RDPEUSB §3.3.5.
//!
//! [`UrbdrcClient`] implements [`DvcProcessor`] for the `"URBDRC"` dynamic
//! virtual channel. It drives the control-channel state machine (capability
//! exchange → channel created) and, on per-device DVCs, dispatches server
//! requests through the [`UrbHandler`] trait for host USB stack integration.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::pdu::{
    hresult_is_success, AddDevice, AddVirtualChannel, CancelRequest, ChannelCreated,
    IoControl, IoControlCompletion, InternalIoControl, Mask, QueryDeviceText, QueryDeviceTextRsp,
    RegisterRequestCallback, RetractDevice, RimExchangeCapabilityRequest,
    RimExchangeCapabilityResponse, SharedMsgHeader, TransferInRequest, TransferOutRequest,
    UrbCompletion, UrbCompletionNoData, UsbDeviceCapabilities, Utf16Multisz, Utf16String,
    CHANNEL_NAME, FN_ADD_DEVICE, FN_CANCEL_REQUEST, FN_INTERNAL_IO_CONTROL,
    FN_IOCONTROL_COMPLETION, FN_IO_CONTROL, FN_QUERY_DEVICE_TEXT, FN_REGISTER_REQUEST_CALLBACK,
    FN_RETRACT_DEVICE, FN_TRANSFER_IN_REQUEST, FN_TRANSFER_OUT_REQUEST, FN_URB_COMPLETION,
    FN_URB_COMPLETION_NO_DATA, HRESULT_S_OK, IID_CAPABILITY_NEGOTIATOR,
    IID_CHANNEL_NOTIFICATION_S2C, IID_DEVICE_SINK, MAX_IN_FLIGHT_REQUESTS_PER_DEVICE,
    MAX_TRANSFER_OUTPUT_BUFFER_SIZE,
};
use crate::ts_urb::{TsUrb, TsUrbResultHeader};

// =============================================================================
// UrbHandler trait
// =============================================================================

/// Result of an IO control operation. MS-RDPEUSB 2.2.7.1
#[derive(Debug, Clone, Default)]
pub struct IoControlResult {
    pub h_result: u32,
    pub information: u32,
    pub output: Vec<u8>,
}

/// Result of a `QUERY_DEVICE_TEXT`. MS-RDPEUSB 2.2.6.6
#[derive(Debug, Clone, Default)]
pub struct QueryDeviceTextResult {
    pub h_result: u32,
    /// UTF-16 code units, without trailing NUL.
    pub description: Vec<u16>,
}

/// Result of a `TRANSFER_IN_REQUEST`. MS-RDPEUSB 2.2.6.7
#[derive(Debug, Clone)]
pub struct TransferInResult {
    /// TS_URB_RESULT_* raw bytes (including the 8-byte header).
    pub urb_result: Vec<u8>,
    pub h_result: u32,
    /// `Some` → emit [`UrbCompletion`], `None` → emit [`UrbCompletionNoData`].
    pub data: Option<Vec<u8>>,
}

/// Result of a `TRANSFER_OUT_REQUEST`. MS-RDPEUSB 2.2.6.8
#[derive(Debug, Clone)]
pub struct TransferOutResult {
    pub urb_result: Vec<u8>,
    pub h_result: u32,
    pub bytes_sent: u32,
}

/// Descriptor returned from [`UrbHandler::list_devices`].
#[derive(Debug, Clone)]
pub struct UsbDeviceDescriptor {
    /// Client-allocated InterfaceId for the device.
    pub usb_device_interface_id: u32,
    pub device_instance_id: Vec<u16>,
    pub hardware_ids: Vec<u16>,
    pub compatibility_ids: Vec<u16>,
    /// GUID string in canonical `{xxxxxxxx-xxxx-...}` form.
    pub container_id: Vec<u16>,
    pub capabilities: UsbDeviceCapabilities,
}

/// Host USB stack trait — all backend integration lives behind this.
pub trait UrbHandler: Send {
    fn list_devices(&mut self) -> Vec<UsbDeviceDescriptor>;
    fn handle_io_control(
        &mut self,
        request_id: u32,
        ioctl: u32,
        input: &[u8],
        output_max: u32,
    ) -> IoControlResult;
    fn handle_internal_io_control(
        &mut self,
        request_id: u32,
        ioctl: u32,
        input: &[u8],
        output_max: u32,
    ) -> IoControlResult;
    /// Handle `QUERY_DEVICE_TEXT`. Note: this message has no RequestId
    /// field — correlation uses the shared header's `MessageId`, which is
    /// passed here for traceability. The response header echoes it back.
    fn handle_query_device_text(
        &mut self,
        message_id: u32,
        text_type: u32,
        locale: u32,
    ) -> QueryDeviceTextResult;
    fn handle_transfer_in(
        &mut self,
        request_id: u32,
        urb: &TsUrb,
        output_max: u32,
    ) -> TransferInResult;
    fn handle_transfer_out(
        &mut self,
        request_id: u32,
        urb: &TsUrb,
        data: &[u8],
    ) -> TransferOutResult;
    fn handle_cancel(&mut self, request_id: u32);
    fn handle_retract(&mut self, reason: u32);
}

// =============================================================================
// MockUrbHandler for tests
// =============================================================================

/// Simple in-memory [`UrbHandler`] implementation. Records all calls for
/// test assertions and returns canned responses.
#[derive(Debug, Default)]
pub struct MockUrbHandler {
    pub devices: Vec<UsbDeviceDescriptor>,
    pub io_control_calls: Vec<(u32, u32)>,
    pub transfer_in_calls: Vec<u32>,
    pub transfer_out_calls: Vec<u32>,
    pub cancelled: Vec<u32>,
    pub retract_reasons: Vec<u32>,
    pub canned_io_result: IoControlResult,
    pub canned_transfer_in: Option<TransferInResult>,
    pub canned_transfer_out: Option<TransferOutResult>,
    pub canned_query_text: QueryDeviceTextResult,
}

impl UrbHandler for MockUrbHandler {
    fn list_devices(&mut self) -> Vec<UsbDeviceDescriptor> {
        self.devices.clone()
    }

    fn handle_io_control(
        &mut self,
        request_id: u32,
        ioctl: u32,
        _input: &[u8],
        _output_max: u32,
    ) -> IoControlResult {
        self.io_control_calls.push((request_id, ioctl));
        self.canned_io_result.clone()
    }

    fn handle_internal_io_control(
        &mut self,
        request_id: u32,
        ioctl: u32,
        _input: &[u8],
        _output_max: u32,
    ) -> IoControlResult {
        self.io_control_calls.push((request_id, ioctl));
        self.canned_io_result.clone()
    }

    fn handle_query_device_text(
        &mut self,
        _message_id: u32,
        _text_type: u32,
        _locale: u32,
    ) -> QueryDeviceTextResult {
        self.canned_query_text.clone()
    }

    fn handle_transfer_in(
        &mut self,
        request_id: u32,
        _urb: &TsUrb,
        _output_max: u32,
    ) -> TransferInResult {
        self.transfer_in_calls.push(request_id);
        self.canned_transfer_in.clone().unwrap_or(TransferInResult {
            urb_result: {
                let mut v = alloc::vec![0u8; 8];
                v[0] = 8;
                v
            },
            h_result: HRESULT_S_OK,
            data: None,
        })
    }

    fn handle_transfer_out(
        &mut self,
        request_id: u32,
        _urb: &TsUrb,
        data: &[u8],
    ) -> TransferOutResult {
        self.transfer_out_calls.push(request_id);
        self.canned_transfer_out
            .clone()
            .unwrap_or(TransferOutResult {
                urb_result: {
                    let mut v = alloc::vec![0u8; 8];
                    v[0] = 8;
                    v
                },
                h_result: HRESULT_S_OK,
                bytes_sent: data.len() as u32,
            })
    }

    fn handle_cancel(&mut self, request_id: u32) {
        self.cancelled.push(request_id);
    }

    fn handle_retract(&mut self, reason: u32) {
        self.retract_reasons.push(reason);
    }
}

// =============================================================================
// Client config & state machine
// =============================================================================

#[derive(Debug, Clone)]
pub struct UrbdrcClientConfig {
    /// Upper bound on in-flight requests per device (DoS cap).
    pub max_in_flight_requests_per_device: usize,
    /// Outbound message ID counter seed.
    pub initial_message_id: u32,
}

impl Default for UrbdrcClientConfig {
    fn default() -> Self {
        Self {
            max_in_flight_requests_per_device: MAX_IN_FLIGHT_REQUESTS_PER_DEVICE,
            initial_message_id: 1,
        }
    }
}

/// Control-channel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlState {
    WaitCapabilityRequest,
    WaitServerChannelCreated,
    Ready,
}

/// Per-device state.
#[derive(Debug)]
#[allow(dead_code)]
struct DeviceState {
    /// Client-allocated `UsbDevice` interface ID.
    usb_device: u32,
    /// Server-allocated `RequestCompletion` interface ID, once received.
    request_completion: Option<u32>,
    /// In-flight request IDs → whether they were TRANSFER_IN (true) or
    /// something else (false).
    in_flight: BTreeMap<u32, bool>,
    /// Closed / retracted.
    closed: bool,
}

// =============================================================================
// UrbdrcClient
// =============================================================================

/// URBDRC DVC client. One instance per DVC (control channel **or** per-device
/// channel). The control instance owns the [`UrbHandler`]; per-device
/// instances share state via the control instance's lookup table when the
/// caller registers them with a `DrdynvcClient`.
///
/// For simplicity this implementation keeps **everything** in a single
/// `UrbdrcClient` so tests can drive it end-to-end over one mock transport.
pub struct UrbdrcClient {
    config: UrbdrcClientConfig,
    handler: Box<dyn UrbHandler>,
    control_state: ControlState,
    next_message_id: u32,
    closed: bool,
    /// Map from `UsbDevice` interface ID → device state.
    devices: BTreeMap<u32, DeviceState>,
}

impl core::fmt::Debug for UrbdrcClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UrbdrcClient")
            .field("control_state", &self.control_state)
            .field("devices", &self.devices.len())
            .field("closed", &self.closed)
            .finish()
    }
}

impl UrbdrcClient {
    pub fn new(handler: Box<dyn UrbHandler>) -> Self {
        Self::with_config(handler, UrbdrcClientConfig::default())
    }

    pub fn with_config(handler: Box<dyn UrbHandler>, config: UrbdrcClientConfig) -> Self {
        let next_message_id = config.initial_message_id;
        Self {
            config,
            handler,
            control_state: ControlState::WaitCapabilityRequest,
            next_message_id,
            closed: false,
            devices: BTreeMap::new(),
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.control_state, ControlState::Ready)
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Borrow the installed handler (for tests).
    pub fn handler(&self) -> &dyn UrbHandler {
        &*self.handler
    }

    pub fn handler_mut(&mut self) -> &mut dyn UrbHandler {
        &mut *self.handler
    }

    fn next_mid(&mut self) -> u32 {
        let v = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        v
    }

    /// Dispatch a raw incoming DVC payload (as if arrived from the server).
    /// Returns outbound messages to send back.
    pub fn dispatch(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if self.closed {
            // Silently ignore after close.
            return Ok(Vec::new());
        }
        if payload.len() < 8 {
            // Malformed — silently ignore (§3.1.5).
            return Ok(Vec::new());
        }
        // Peek at the first word to learn Mask and InterfaceId.
        let word0 = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let interface_id = word0 & SharedMsgHeader::INTERFACE_ID_MASK;
        let mask_bits = (word0 >> 30) & 0x3;
        let mask = match Mask::from_bits(mask_bits) {
            Some(m) => m,
            None => return Ok(Vec::new()),
        };

        // Response-form packets (STREAM_ID_STUB / STREAM_ID_NONE for RIM) are
        // only sent server→client for RIM_EXCHANGE_CAPABILITY_RESPONSE. In
        // practice the server drives us; anything that looks like a response
        // is ignored silently.
        if mask == Mask::StreamIdStub {
            return Ok(Vec::new());
        }

        match interface_id {
            IID_CAPABILITY_NEGOTIATOR => self.handle_capability(payload),
            IID_CHANNEL_NOTIFICATION_S2C => self.handle_channel_created(payload),
            IID_DEVICE_SINK => {
                // Server never sends Device Sink messages (client → server).
                Ok(Vec::new())
            }
            _ => {
                // Per-device server-sourced message (USB Device Interface).
                // Reject device traffic before the capability handshake
                // completes — a server that sends TRANSFER requests pre-Ready
                // is either malformed or hostile. Silently ignore rather than
                // terminate (§3.1.5 out-of-sequence → ignore).
                if self.control_state != ControlState::Ready {
                    return Ok(Vec::new());
                }
                self.handle_device_message(interface_id, payload)
            }
        }
    }

    fn handle_capability(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        // State guard: re-sending capability after handshake complete is an
        // out-of-sequence packet per §3.1.5 → silently ignore (do NOT reset).
        if self.control_state != ControlState::WaitCapabilityRequest {
            return Ok(Vec::new());
        }
        let mut src = ReadCursor::new(payload);
        let req = match RimExchangeCapabilityRequest::decode(&mut src) {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()), // malformed → ignore (§3.1.5)
        };
        // Respond.
        let rsp = RimExchangeCapabilityResponse::new(req.header.message_id, HRESULT_S_OK);
        let mut out = Vec::new();
        out.push(encode_pdu(&rsp)?);

        // Advance state; wait for server CHANNEL_CREATED.
        self.control_state = ControlState::WaitServerChannelCreated;
        Ok(out)
    }

    fn handle_channel_created(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        // State guard: replayed CHANNEL_CREATED after Ready → ignore.
        if self.control_state != ControlState::WaitServerChannelCreated {
            return Ok(Vec::new());
        }
        let mut src = ReadCursor::new(payload);
        let srv = match ChannelCreated::decode(&mut src) {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        if srv.validate_version().is_err() {
            // Version mismatch — close DVC (§3.2.5.2.2).
            self.closed = true;
            return Ok(Vec::new());
        }
        // Emit client CHANNEL_CREATED and enter Ready.
        let ours = ChannelCreated::client(self.next_mid());
        let msg = encode_pdu(&ours)?;
        self.control_state = ControlState::Ready;
        Ok(alloc::vec![msg])
    }

    fn handle_device_message(
        &mut self,
        interface_id: u32,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
        // Peek FunctionId (u32 at offset 8).
        if payload.len() < 12 {
            return Ok(Vec::new());
        }
        let function_id =
            u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);

        match function_id {
            FN_CANCEL_REQUEST => self.handle_cancel_request(payload),
            FN_REGISTER_REQUEST_CALLBACK => self.handle_register_callback(interface_id, payload),
            FN_IO_CONTROL => self.handle_io_control(interface_id, payload, false),
            FN_INTERNAL_IO_CONTROL => self.handle_io_control(interface_id, payload, true),
            FN_QUERY_DEVICE_TEXT => self.handle_query_device_text(interface_id, payload),
            FN_TRANSFER_IN_REQUEST => self.handle_transfer_in(interface_id, payload),
            FN_TRANSFER_OUT_REQUEST => self.handle_transfer_out(interface_id, payload),
            FN_RETRACT_DEVICE => self.handle_retract(interface_id, payload),
            _ => Ok(Vec::new()),
        }
    }

    fn handle_cancel_request(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        let mut src = ReadCursor::new(payload);
        let req = match CancelRequest::decode(&mut src) {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        self.handler.handle_cancel(req.request_id);
        Ok(Vec::new())
    }

    fn handle_register_callback(
        &mut self,
        interface_id: u32,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
        let mut src = ReadCursor::new(payload);
        let req = match RegisterRequestCallback::decode(&mut src) {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        let dev = self
            .devices
            .entry(interface_id)
            .or_insert_with(|| DeviceState {
                usb_device: interface_id,
                request_completion: None,
                in_flight: BTreeMap::new(),
                closed: false,
            });
        dev.request_completion = req.request_completion;
        Ok(Vec::new())
    }

    fn device_completion_iid(&self, device: u32) -> Option<u32> {
        self.devices
            .get(&device)
            .and_then(|d| d.request_completion)
    }

    fn record_in_flight(
        &mut self,
        device: u32,
        request_id: u32,
        is_transfer_in: bool,
    ) -> Result<(), DvcError> {
        let cap = self.config.max_in_flight_requests_per_device;
        let dev = self
            .devices
            .entry(device)
            .or_insert_with(|| DeviceState {
                usb_device: device,
                request_completion: None,
                in_flight: BTreeMap::new(),
                closed: false,
            });
        if dev.in_flight.len() >= cap {
            return Err(DvcError::Protocol(format!(
                "device {} exceeded in-flight cap",
                device
            )));
        }
        dev.in_flight.insert(request_id, is_transfer_in);
        Ok(())
    }

    fn retire_in_flight(&mut self, device: u32, request_id: u32) {
        if let Some(d) = self.devices.get_mut(&device) {
            d.in_flight.remove(&request_id);
        }
    }

    fn handle_io_control(
        &mut self,
        interface_id: u32,
        payload: &[u8],
        internal: bool,
    ) -> DvcResult<Vec<DvcMessage>> {
        let mut src = ReadCursor::new(payload);
        let (io_code, input, output_max, request_id) = if internal {
            let pdu = match InternalIoControl::decode(&mut src) {
                Ok(v) => v,
                Err(_) => return Ok(Vec::new()),
            };
            (
                pdu.io_control_code,
                pdu.input_buffer,
                pdu.output_buffer_size,
                pdu.request_id,
            )
        } else {
            let pdu = match IoControl::decode(&mut src) {
                Ok(v) => v,
                Err(_) => return Ok(Vec::new()),
            };
            (
                pdu.io_control_code,
                pdu.input_buffer,
                pdu.output_buffer_size,
                pdu.request_id,
            )
        };

        // Protocol violation: IO_CONTROL before REGISTER_REQUEST_CALLBACK
        // with non-zero RequestCompletion → close DVC (§3.2.5.4.1, checklist §6.2).
        let completion_iid = match self.device_completion_iid(interface_id) {
            Some(v) => v,
            None => {
                self.closed = true;
                return Err(DvcError::Protocol(
                    "IO_CONTROL before REGISTER_REQUEST_CALLBACK".to_string(),
                ));
            }
        };

        self.record_in_flight(interface_id, request_id, false)?;

        let result = if internal {
            self.handler
                .handle_internal_io_control(request_id, io_code, &input, output_max)
        } else {
            self.handler
                .handle_io_control(request_id, io_code, &input, output_max)
        };

        // Build IOCONTROL_COMPLETION.
        let IoControlResult {
            h_result,
            information,
            output,
        } = result;
        // Enforce completion rules (§2.2.7.1).
        let (info_field, out_buf) = if hresult_is_success(h_result) {
            (output.len() as u32, output)
        } else if h_result == crate::pdu::HRESULT_FROM_WIN32_ERROR_INSUFFICIENT_BUFFER {
            // §2.2.7.1: OutputBufferSize MUST echo request.OutputBufferSize
            // (and Information carries the actually-needed size). The buffer
            // field itself follows the spec wire layout — OutputBufferSize
            // bytes — so we pad with zeros since the handler has nothing
            // useful to return.
            //
            // Defense-in-depth: the PDU decoder already caps
            // `output_max` at MAX_IOCTL_BUFFER_SIZE, but re-check locally so
            // a future refactor can't introduce an unchecked allocation.
            if output_max > crate::pdu::MAX_IOCTL_BUFFER_SIZE {
                self.closed = true;
                return Err(DvcError::Protocol(
                    "output_max exceeds MAX_IOCTL_BUFFER_SIZE".to_string(),
                ));
            }
            (information, alloc::vec![0u8; output_max as usize])
        } else {
            (0, alloc::vec::Vec::new())
        };

        if out_buf.len() as u32 > output_max {
            // Handler returned more than the server permitted → protocol
            // violation on our side; close DVC rather than lie.
            self.closed = true;
            return Err(DvcError::Protocol(
                "handler output_buffer > request.OutputBufferSize".to_string(),
            ));
        }

        let completion = IoControlCompletion {
            header: SharedMsgHeader::request(
                completion_iid,
                Mask::StreamIdProxy,
                self.next_mid(),
                FN_IOCONTROL_COMPLETION,
            ),
            request_id,
            h_result,
            information: info_field,
            output_buffer_size: out_buf.len() as u32,
            output_buffer: out_buf,
        };
        self.retire_in_flight(interface_id, request_id);
        Ok(alloc::vec![encode_pdu(&completion)?])
    }

    fn handle_query_device_text(
        &mut self,
        interface_id: u32,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
        let mut src = ReadCursor::new(payload);
        let req = match QueryDeviceText::decode(&mut src) {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        let result = self
            .handler
            .handle_query_device_text(req.header.message_id, req.text_type, req.locale_id);
        let desc = if result.description.is_empty() {
            None
        } else {
            Some(Utf16String::new(result.description))
        };
        let rsp = QueryDeviceTextRsp {
            header: SharedMsgHeader::response(interface_id, req.header.message_id),
            device_description: desc,
            h_result: result.h_result,
        };
        Ok(alloc::vec![encode_pdu(&rsp)?])
    }

    fn handle_transfer_in(
        &mut self,
        interface_id: u32,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
        let mut src = ReadCursor::new(payload);
        let req = match TransferInRequest::decode(&mut src) {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        let completion_iid = match self.device_completion_iid(interface_id) {
            Some(v) => v,
            None => {
                self.closed = true;
                return Err(DvcError::Protocol(
                    "TRANSFER_IN_REQUEST before REGISTER_REQUEST_CALLBACK".to_string(),
                ));
            }
        };

        let urb = match TsUrb::decode(&req.ts_urb) {
            Ok(u) => u,
            Err(_) => return Ok(Vec::new()),
        };
        let request_id = urb.header().request_id;
        self.record_in_flight(interface_id, request_id, true)?;

        let result = self
            .handler
            .handle_transfer_in(request_id, &urb, req.output_buffer_size);

        let TransferInResult {
            urb_result,
            h_result,
            data,
        } = result;

        if urb_result.len() < TsUrbResultHeader::WIRE_SIZE {
            return Err(DvcError::Protocol("urb_result too small".to_string()));
        }
        if urb_result.len() > u16::MAX as usize {
            return Err(DvcError::Protocol(
                "urb_result exceeds u16::MAX (TS_URB_RESULT_HEADER.Size)".to_string(),
            ));
        }
        // Force TS_URB_RESULT_HEADER.Size to match urb_result.len() (safety).
        let mut urb_result = urb_result;
        let size = urb_result.len() as u16;
        urb_result[0..2].copy_from_slice(&size.to_le_bytes());

        let msgs = if let Some(data) = data {
            if data.len() as u32 > req.output_buffer_size
                || data.len() as u32 > MAX_TRANSFER_OUTPUT_BUFFER_SIZE
            {
                self.closed = true;
                return Err(DvcError::Protocol(
                    "TRANSFER_IN: handler data exceeds request output_buffer_size".to_string(),
                ));
            }
            let completion = UrbCompletion {
                header: SharedMsgHeader::request(
                    completion_iid,
                    Mask::StreamIdProxy,
                    self.next_mid(),
                    FN_URB_COMPLETION,
                ),
                request_id,
                cb_ts_urb_result: urb_result.len() as u32,
                ts_urb_result: urb_result,
                h_result,
                output_buffer_size: data.len() as u32,
                output_buffer: data,
            };
            alloc::vec![encode_pdu(&completion)?]
        } else {
            // No data — use URB_COMPLETION_NO_DATA with OutputBufferSize = 0
            // (§3.3.5.3.6 + §2.2.7.3 TRANSFER_IN rule).
            let completion = UrbCompletionNoData {
                header: SharedMsgHeader::request(
                    completion_iid,
                    Mask::StreamIdProxy,
                    self.next_mid(),
                    FN_URB_COMPLETION_NO_DATA,
                ),
                request_id,
                cb_ts_urb_result: urb_result.len() as u32,
                ts_urb_result: urb_result,
                h_result,
                output_buffer_size: 0,
            };
            alloc::vec![encode_pdu(&completion)?]
        };

        self.retire_in_flight(interface_id, request_id);
        Ok(msgs)
    }

    fn handle_transfer_out(
        &mut self,
        interface_id: u32,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
        let mut src = ReadCursor::new(payload);
        let req = match TransferOutRequest::decode(&mut src) {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        let completion_iid = match self.device_completion_iid(interface_id) {
            Some(v) => v,
            None => {
                self.closed = true;
                return Err(DvcError::Protocol(
                    "TRANSFER_OUT_REQUEST before REGISTER_REQUEST_CALLBACK".to_string(),
                ));
            }
        };
        let urb = match TsUrb::decode(&req.ts_urb) {
            Ok(u) => u,
            Err(_) => return Ok(Vec::new()),
        };
        let request_id = urb.header().request_id;
        self.record_in_flight(interface_id, request_id, false)?;

        // NoAck isoch out → no completion emitted.
        if urb.header().no_ack
            && urb.header().function == crate::ts_urb::URB_FUNCTION_ISOCH_TRANSFER
        {
            let _ = self
                .handler
                .handle_transfer_out(request_id, &urb, &req.output_buffer);
            self.retire_in_flight(interface_id, request_id);
            return Ok(Vec::new());
        }

        let result = self
            .handler
            .handle_transfer_out(request_id, &urb, &req.output_buffer);
        let TransferOutResult {
            urb_result,
            h_result,
            bytes_sent,
        } = result;

        if urb_result.len() < TsUrbResultHeader::WIRE_SIZE {
            return Err(DvcError::Protocol("urb_result too small".to_string()));
        }
        if urb_result.len() > u16::MAX as usize {
            return Err(DvcError::Protocol(
                "urb_result exceeds u16::MAX (TS_URB_RESULT_HEADER.Size)".to_string(),
            ));
        }
        let mut urb_result = urb_result;
        let size = urb_result.len() as u16;
        urb_result[0..2].copy_from_slice(&size.to_le_bytes());

        if bytes_sent > req.output_buffer_size {
            self.closed = true;
            return Err(DvcError::Protocol(
                "TRANSFER_OUT: bytes_sent > request.OutputBufferSize".to_string(),
            ));
        }
        let completion = UrbCompletionNoData {
            header: SharedMsgHeader::request(
                completion_iid,
                Mask::StreamIdProxy,
                self.next_mid(),
                FN_URB_COMPLETION_NO_DATA,
            ),
            request_id,
            cb_ts_urb_result: urb_result.len() as u32,
            ts_urb_result: urb_result,
            h_result,
            output_buffer_size: bytes_sent,
        };
        self.retire_in_flight(interface_id, request_id);
        Ok(alloc::vec![encode_pdu(&completion)?])
    }

    fn handle_retract(
        &mut self,
        interface_id: u32,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
        let mut src = ReadCursor::new(payload);
        let req = match RetractDevice::decode(&mut src) {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        self.handler.handle_retract(req.reason);
        if let Some(dev) = self.devices.get_mut(&interface_id) {
            dev.closed = true;
        }
        self.closed = true;
        Ok(Vec::new())
    }

    /// Build an `ADD_VIRTUAL_CHANNEL` message (client → server on the control
    /// channel). Available once the control channel is Ready.
    pub fn build_add_virtual_channel(&mut self) -> DvcResult<DvcMessage> {
        if !self.is_ready() {
            return Err(DvcError::Protocol("control channel not Ready".to_string()));
        }
        let pdu = AddVirtualChannel::new(self.next_mid());
        encode_pdu(&pdu)
    }

    /// Build an `ADD_DEVICE` message (client → server on a per-device channel).
    pub fn build_add_device(
        &mut self,
        descriptor: &UsbDeviceDescriptor,
    ) -> DvcResult<DvcMessage> {
        let pdu = AddDevice {
            header: SharedMsgHeader::request(
                IID_DEVICE_SINK,
                Mask::StreamIdProxy,
                self.next_mid(),
                FN_ADD_DEVICE,
            ),
            num_usb_device: 1,
            usb_device: descriptor.usb_device_interface_id,
            device_instance_id: Utf16String::new(descriptor.device_instance_id.clone()),
            hardware_ids: if descriptor.hardware_ids.is_empty() {
                None
            } else {
                Some(Utf16Multisz {
                    raw: descriptor.hardware_ids.clone(),
                })
            },
            compatibility_ids: if descriptor.compatibility_ids.is_empty() {
                None
            } else {
                Some(Utf16Multisz {
                    raw: descriptor.compatibility_ids.clone(),
                })
            },
            container_id: Utf16String::new(descriptor.container_id.clone()),
            usb_device_capabilities: descriptor.capabilities,
        };
        // Register the device so later REGISTER_REQUEST_CALLBACK can find it.
        self.devices.insert(
            descriptor.usb_device_interface_id,
            DeviceState {
                usb_device: descriptor.usb_device_interface_id,
                request_completion: None,
                in_flight: BTreeMap::new(),
                closed: false,
            },
        );
        encode_pdu(&pdu)
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn encode_pdu<E: Encode>(pdu: &E) -> DvcResult<DvcMessage> {
    let size = pdu.size();
    let mut buf = alloc::vec![0u8; size];
    let mut dst = WriteCursor::new(&mut buf);
    pdu.encode(&mut dst).map_err(DvcError::Encode)?;
    Ok(DvcMessage::new(buf))
}

// =============================================================================
// DvcProcessor impl
// =============================================================================

impl AsAny for UrbdrcClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl DvcProcessor for UrbdrcClient {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        // Server speaks first.
        Ok(Vec::new())
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.dispatch(payload)
    }

    fn close(&mut self, _channel_id: u32) {
        self.closed = true;
        self.devices.clear();
        self.control_state = ControlState::WaitCapabilityRequest;
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ts_urb::{
        TsUrbBulkOrInterruptTransfer, TsUrbHeader, URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER,
    };

    fn descriptor() -> UsbDeviceDescriptor {
        let caps = UsbDeviceCapabilities {
            cb_size: 28,
            usb_bus_interface_version: 2,
            usbdi_version: 0x500,
            supported_usb_version: 0x0200,
            hcd_capabilities: 0,
            device_is_high_speed: 1,
            no_ack_isoch_write_jitter_buffer_size_in_ms: 0,
        };
        UsbDeviceDescriptor {
            usb_device_interface_id: 0x0000_1000,
            device_instance_id: "USB\\VID_1234&PID_5678".encode_utf16().collect(),
            hardware_ids: {
                let mut v: Vec<u16> = "USB\\VID_1234".encode_utf16().collect();
                v.push(0);
                v.push(0);
                v
            },
            compatibility_ids: {
                let mut v: Vec<u16> = "USB\\Class_03".encode_utf16().collect();
                v.push(0);
                v.push(0);
                v
            },
            container_id: "{11112222-3333-4444-5555-666677778888}"
                .encode_utf16()
                .collect(),
            capabilities: caps,
        }
    }

    #[test]
    fn capability_exchange_produces_response_and_waits_for_channel_created() {
        let mut c = UrbdrcClient::new(Box::new(MockUrbHandler::default()));
        let req = RimExchangeCapabilityRequest::new(1);
        let mut buf = alloc::vec![0u8; req.size()];
        let mut cur = WriteCursor::new(&mut buf);
        req.encode(&mut cur).unwrap();
        let out = c.dispatch(&buf).unwrap();
        assert_eq!(out.len(), 1);
        assert!(matches!(c.control_state, ControlState::WaitServerChannelCreated));
    }

    #[test]
    fn replayed_capability_request_after_ready_is_ignored() {
        let mut c = UrbdrcClient::new(Box::new(MockUrbHandler::default()));
        c.control_state = ControlState::Ready;
        let req = RimExchangeCapabilityRequest::new(1);
        let mut buf = alloc::vec![0u8; req.size()];
        let mut cur = WriteCursor::new(&mut buf);
        req.encode(&mut cur).unwrap();
        let out = c.dispatch(&buf).unwrap();
        assert!(out.is_empty());
        assert!(matches!(c.control_state, ControlState::Ready));
    }

    #[test]
    fn replayed_channel_created_after_ready_is_ignored() {
        let mut c = UrbdrcClient::new(Box::new(MockUrbHandler::default()));
        c.control_state = ControlState::Ready;
        let cc = ChannelCreated::server(7);
        let mut buf = alloc::vec![0u8; cc.size()];
        let mut cur = WriteCursor::new(&mut buf);
        cc.encode(&mut cur).unwrap();
        let out = c.dispatch(&buf).unwrap();
        assert!(out.is_empty());
        assert!(matches!(c.control_state, ControlState::Ready));
    }

    #[test]
    fn device_message_before_ready_is_ignored() {
        let mut c = UrbdrcClient::new(Box::new(MockUrbHandler::default()));
        // Default state is WaitCapabilityRequest — device msg must be ignored.
        let dev = 0x0000_1000;
        let retract = RetractDevice {
            header: SharedMsgHeader::request(dev, Mask::StreamIdProxy, 1, FN_RETRACT_DEVICE),
            reason: crate::pdu::USB_RETRACT_REASON_BLOCKED_BY_POLICY,
        };
        let mut buf = alloc::vec![0u8; retract.size()];
        let mut cur = WriteCursor::new(&mut buf);
        retract.encode(&mut cur).unwrap();
        let out = c.dispatch(&buf).unwrap();
        assert!(out.is_empty());
        assert!(!c.is_closed());
    }

    #[test]
    fn channel_created_transitions_to_ready_and_emits_client_channel_created() {
        let mut c = UrbdrcClient::new(Box::new(MockUrbHandler::default()));
        // Skip cap exchange directly.
        c.control_state = ControlState::WaitServerChannelCreated;
        let cc = ChannelCreated::server(7);
        let mut buf = alloc::vec![0u8; cc.size()];
        let mut cur = WriteCursor::new(&mut buf);
        cc.encode(&mut cur).unwrap();
        let out = c.dispatch(&buf).unwrap();
        assert_eq!(out.len(), 1);
        assert!(c.is_ready());
    }

    #[test]
    fn io_control_before_register_closes_dvc() {
        let mut c = UrbdrcClient::new(Box::new(MockUrbHandler::default()));
        c.control_state = ControlState::Ready;
        let dev = 0x0000_1000;
        let pdu = IoControl {
            header: SharedMsgHeader::request(dev, Mask::StreamIdProxy, 1, FN_IO_CONTROL),
            io_control_code: 0x22_0000,
            input_buffer: Vec::new(),
            output_buffer_size: 4,
            request_id: 1,
        };
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        let err = c.dispatch(&buf).unwrap_err();
        match err {
            DvcError::Protocol(_) => {}
            _ => panic!("expected protocol error"),
        }
        assert!(c.is_closed());
    }

    #[test]
    fn io_control_after_register_returns_completion() {
        let mut c = UrbdrcClient::new(Box::new(MockUrbHandler::default()));
        c.control_state = ControlState::Ready;
        let dev = 0x0000_1000;
        // REGISTER first.
        let reg = RegisterRequestCallback::new(dev, 1, 0x0000_2000);
        let mut buf = alloc::vec![0u8; reg.size()];
        let mut cur = WriteCursor::new(&mut buf);
        reg.encode(&mut cur).unwrap();
        c.dispatch(&buf).unwrap();
        // Then IO_CONTROL.
        let pdu = IoControl {
            header: SharedMsgHeader::request(dev, Mask::StreamIdProxy, 2, FN_IO_CONTROL),
            io_control_code: 0x22_0000,
            input_buffer: alloc::vec![1, 2, 3],
            output_buffer_size: 16,
            request_id: 42,
        };
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        let out = c.dispatch(&buf).unwrap();
        assert_eq!(out.len(), 1);
        // Decode the completion.
        let mut src = ReadCursor::new(&out[0].data);
        let comp = IoControlCompletion::decode(&mut src).unwrap();
        assert_eq!(comp.request_id, 42);
        assert_eq!(comp.h_result, HRESULT_S_OK);
    }

    #[test]
    fn transfer_in_returns_urb_completion_no_data_when_no_data() {
        let mut c = UrbdrcClient::new(Box::new(MockUrbHandler::default()));
        c.control_state = ControlState::Ready;
        let dev = 0x0000_1000;
        let reg = RegisterRequestCallback::new(dev, 1, 0x0000_2000);
        let mut buf = alloc::vec![0u8; reg.size()];
        let mut cur = WriteCursor::new(&mut buf);
        reg.encode(&mut cur).unwrap();
        c.dispatch(&buf).unwrap();
        // Build a TS_URB_BULK_OR_INTERRUPT_TRANSFER.
        let urb = TsUrb::BulkOrInterruptTransfer(TsUrbBulkOrInterruptTransfer {
            header: TsUrbHeader::new(
                TsUrbBulkOrInterruptTransfer::WIRE_SIZE as u16,
                URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER,
                77,
            ),
            pipe_handle: 1,
            transfer_flags: 0,
        });
        let ts_urb = urb.encode_to_vec().unwrap();
        let req = TransferInRequest {
            header: SharedMsgHeader::request(
                dev,
                Mask::StreamIdProxy,
                2,
                FN_TRANSFER_IN_REQUEST,
            ),
            cb_ts_urb: ts_urb.len() as u32,
            ts_urb,
            output_buffer_size: 64,
        };
        let mut buf = alloc::vec![0u8; req.size()];
        let mut cur = WriteCursor::new(&mut buf);
        req.encode(&mut cur).unwrap();
        let out = c.dispatch(&buf).unwrap();
        assert_eq!(out.len(), 1);
        let mut src = ReadCursor::new(&out[0].data);
        let comp = UrbCompletionNoData::decode(&mut src).unwrap();
        assert_eq!(comp.request_id, 77);
        assert_eq!(comp.output_buffer_size, 0);
    }

    #[test]
    fn retract_device_closes_channel() {
        let mut c = UrbdrcClient::new(Box::new(MockUrbHandler::default()));
        c.control_state = ControlState::Ready;
        let dev = 0x0000_1000;
        let retract = RetractDevice {
            header: SharedMsgHeader::request(dev, Mask::StreamIdProxy, 1, FN_RETRACT_DEVICE),
            reason: crate::pdu::USB_RETRACT_REASON_BLOCKED_BY_POLICY,
        };
        let mut buf = alloc::vec![0u8; retract.size()];
        let mut cur = WriteCursor::new(&mut buf);
        retract.encode(&mut cur).unwrap();
        c.dispatch(&buf).unwrap();
        assert!(c.is_closed());
    }

    #[test]
    fn malformed_payload_ignored_silently() {
        let mut c = UrbdrcClient::new(Box::new(MockUrbHandler::default()));
        let out = c.dispatch(&[0u8; 3]).unwrap();
        assert!(out.is_empty());
        assert!(!c.is_closed());
    }

    #[test]
    fn build_add_virtual_channel_requires_ready() {
        let mut c = UrbdrcClient::new(Box::new(MockUrbHandler::default()));
        assert!(c.build_add_virtual_channel().is_err());
        c.control_state = ControlState::Ready;
        assert!(c.build_add_virtual_channel().is_ok());
    }

    #[test]
    fn build_add_device_registers_slot() {
        let mut c = UrbdrcClient::new(Box::new(MockUrbHandler::default()));
        let d = descriptor();
        c.build_add_device(&d).unwrap();
        assert!(c.devices.contains_key(&0x0000_1000));
    }
}
