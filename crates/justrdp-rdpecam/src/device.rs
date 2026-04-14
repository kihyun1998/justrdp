//! [`RdpecamDeviceClient`] -- per-device DVC processor.
//!
//! Drives one camera through its full lifecycle:
//!
//! ```text
//!   start()                                     close()
//!     │                                            ▲
//!     ▼                                            │
//!   Initialised  ── ActivateDeviceRequest ──►  Activated (streaming=false)
//!        ▲                                         │   ▲
//!        │                                         │   │
//!        │                      StartStreamsRequest│   │ StopStreamsRequest
//!        │                                         ▼   │
//!        └─────── DeactivateDeviceRequest ◄──  Streaming (Activated w/ streaming=true)
//! ```
//!
//! Protocol decisions encoded here (see `specs/ms-rdpecam-checklist.md`
//! §8 for the authoritative validation matrix):
//!
//! - Messages whose MessageId falls outside `0x01..=0x18` produce an
//!   `ErrorResponse(InvalidMessage)` and leave state untouched.
//! - v2-only message ids (0x14..=0x18) received when the negotiated
//!   version is 1 produce `ErrorResponse(InvalidMessage)`.
//! - Host-level failures are translated through [`CamError::to_error_code`];
//!   for `SampleRequest` specifically the reply is
//!   `SampleErrorResponse(stream_index, error_code)` so the server can
//!   correlate with the in-flight stream.
//! - `DeactivateDeviceRequest` received while streaming calls
//!   `stop_streams()` internally before `deactivate()`, mirroring the
//!   forgiving behaviour Windows clients exhibit.
//! - `ErrorResponse` / `SuccessResponse` / `SampleResponse` messages
//!   from the server are treated as protocol errors because this
//!   processor is the client side and the server is never supposed to
//!   send those.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Encode};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::camera::CameraDevice;
use crate::constants::{
    is_v2_only, ErrorCode, MSG_ACTIVATE_DEVICE_REQUEST, MSG_CURRENT_MEDIA_TYPE_REQUEST,
    MSG_DEACTIVATE_DEVICE_REQUEST, MSG_MEDIA_TYPE_LIST_REQUEST, MSG_PROPERTY_LIST_REQUEST,
    MSG_PROPERTY_VALUE_REQUEST, MSG_SAMPLE_REQUEST, MSG_SET_PROPERTY_VALUE_REQUEST,
    MSG_START_STREAMS_REQUEST, MSG_STOP_STREAMS_REQUEST, MSG_STREAM_LIST_REQUEST,
};
use crate::pdu::capture::{
    SampleErrorResponse, SampleRequest, SampleResponse, StartStreamsRequest, StopStreamsRequest,
};
use crate::pdu::device::{
    ActivateDeviceRequest, DeactivateDeviceRequest, ErrorResponse, SuccessResponse,
};
use crate::pdu::encode_to_vec;
use crate::pdu::property::{
    PropertyListRequest, PropertyListResponse, PropertyValueRequest, PropertyValueResponse,
    SetPropertyValueRequest,
};
use crate::pdu::stream::{
    CurrentMediaTypeRequest, CurrentMediaTypeResponse, MediaTypeListRequest,
    MediaTypeListResponse, StreamListRequest, StreamListResponse,
};
use justrdp_core::{Decode, ReadCursor};

/// Internal lifecycle of the device processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceState {
    /// `start()` has not been called yet.
    Uninitialised,
    /// Channel is open but `ActivateDeviceRequest` has not been seen.
    Initialised,
    /// Device is activated. `streaming` tracks whether `StartStreams`
    /// has put the device into the sample-producing substate.
    Activated { streaming: bool },
    /// Channel has been closed.
    Closed,
}

/// DVC processor for one camera device's per-device DVC.
///
/// The channel name is supplied at construction time and must match
/// exactly the `VirtualChannelName` that was placed into the
/// corresponding `DeviceAddedNotification`. The host is responsible for
/// calling `DrdynvcClient::register` with the boxed instance BEFORE
/// announcing the device on the enumerator channel.
pub struct RdpecamDeviceClient {
    device: Box<dyn CameraDevice>,
    /// Exact ANSI bytes of the per-device DVC name. Stored as a String
    /// because `DvcProcessor::channel_name` returns `&str`.
    channel_name: String,
    negotiated_version: u8,
    state: DeviceState,
    channel_id: u32,
}

impl core::fmt::Debug for RdpecamDeviceClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdpecamDeviceClient")
            .field("channel_name", &self.channel_name)
            .field("negotiated_version", &self.negotiated_version)
            .field("state", &self.state)
            .field("channel_id", &self.channel_id)
            .finish()
    }
}

impl RdpecamDeviceClient {
    /// Constructs a new per-device processor bound to a specific channel
    /// name and protocol version.
    ///
    /// `channel_name` MUST match the `VirtualChannelName` placed in the
    /// `DeviceAddedNotification` that advertised this camera. Behaviour
    /// is undefined (server-side routing failure) if the two disagree.
    ///
    /// `negotiated_version` is the version returned by the enumerator's
    /// `SelectVersionResponse` handshake. Passing 1 disables the property
    /// API; passing 2 enables it.
    pub fn new(
        channel_name: String,
        negotiated_version: u8,
        device: Box<dyn CameraDevice>,
    ) -> Self {
        Self {
            device,
            channel_name,
            negotiated_version,
            state: DeviceState::Uninitialised,
            channel_id: 0,
        }
    }

    /// Returns true iff `start()` has been called and `close()` has not.
    pub fn is_open(&self) -> bool {
        !matches!(
            self.state,
            DeviceState::Uninitialised | DeviceState::Closed
        )
    }

    /// Returns true iff the device is past `ActivateDeviceRequest`.
    pub fn is_activated(&self) -> bool {
        matches!(self.state, DeviceState::Activated { .. })
    }

    /// Returns true iff the device is currently producing samples.
    pub fn is_streaming(&self) -> bool {
        matches!(self.state, DeviceState::Activated { streaming: true })
    }

    // ── Internal response helpers ──

    fn success(&self) -> SuccessResponse {
        SuccessResponse::new(self.negotiated_version)
    }

    fn error(&self, code: ErrorCode) -> ErrorResponse {
        ErrorResponse::new(self.negotiated_version, code)
    }

    /// Encodes a single PDU into a heap-allocated `DvcMessage`, bubbling
    /// up wire-format encoding failures as `DvcError::Encode`.
    fn one<P: Encode>(pdu: &P) -> DvcResult<Vec<DvcMessage>> {
        let bytes = encode_to_vec(pdu).map_err(DvcError::Encode)?;
        Ok(alloc::vec![DvcMessage::new(bytes)])
    }

    /// Builds a singleton response vector carrying `ErrorResponse(code)`
    /// using the negotiated protocol version.
    fn err_response(&self, code: ErrorCode) -> DvcResult<Vec<DvcMessage>> {
        Self::one(&self.error(code))
    }

    // ── Per-message handlers ──

    fn on_activate(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        // Validate the concrete PDU shape.
        decode_exact::<ActivateDeviceRequest>(payload)?;
        if self.is_activated() {
            // Double activation -- treat as protocol error per §8.
            return self.err_response(ErrorCode::InvalidRequest);
        }
        match self.device.activate() {
            Ok(()) => {
                self.state = DeviceState::Activated { streaming: false };
                Self::one(&self.success())
            }
            Err(e) => self.err_response(e.to_error_code()),
        }
    }

    fn on_deactivate(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        decode_exact::<DeactivateDeviceRequest>(payload)?;
        if !self.is_activated() {
            return self.err_response(ErrorCode::NotInitialized);
        }
        // If streams are running, shut them down gracefully before
        // deactivating -- matches the lenient behaviour Windows clients
        // exhibit and avoids leaking a half-streaming device on the
        // host side.
        if self.is_streaming() {
            if let Err(e) = self.device.stop_streams() {
                return self.err_response(e.to_error_code());
            }
        }
        match self.device.deactivate() {
            Ok(()) => {
                self.state = DeviceState::Initialised;
                Self::one(&self.success())
            }
            Err(e) => self.err_response(e.to_error_code()),
        }
    }

    fn on_stream_list(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        decode_exact::<StreamListRequest>(payload)?;
        if !self.is_activated() {
            return self.err_response(ErrorCode::NotInitialized);
        }
        let resp = StreamListResponse {
            version: self.negotiated_version,
            streams: self.device.stream_list().to_vec(),
        };
        Self::one(&resp)
    }

    fn on_media_type_list(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        let req = decode_exact::<MediaTypeListRequest>(payload)?;
        if !self.is_activated() {
            return self.err_response(ErrorCode::NotInitialized);
        }
        match self.device.media_type_list(req.stream_index) {
            Ok(list) => {
                let resp = MediaTypeListResponse {
                    version: self.negotiated_version,
                    media_types: list.to_vec(),
                };
                Self::one(&resp)
            }
            Err(e) => self.err_response(e.to_error_code()),
        }
    }

    fn on_current_media_type(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        let req = decode_exact::<CurrentMediaTypeRequest>(payload)?;
        if !self.is_activated() {
            return self.err_response(ErrorCode::NotInitialized);
        }
        match self.device.current_media_type(req.stream_index) {
            Ok(mt) => Self::one(&CurrentMediaTypeResponse::new(self.negotiated_version, mt)),
            Err(e) => self.err_response(e.to_error_code()),
        }
    }

    fn on_start_streams(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        let req = decode_exact::<StartStreamsRequest>(payload)?;
        if !self.is_activated() {
            return self.err_response(ErrorCode::NotInitialized);
        }
        match self.device.start_streams(&req.infos) {
            Ok(()) => {
                self.state = DeviceState::Activated { streaming: true };
                Self::one(&self.success())
            }
            Err(e) => self.err_response(e.to_error_code()),
        }
    }

    fn on_stop_streams(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        decode_exact::<StopStreamsRequest>(payload)?;
        if !self.is_streaming() {
            // StopStreams before StartStreams is a protocol error per §8.
            return self.err_response(ErrorCode::NotInitialized);
        }
        match self.device.stop_streams() {
            Ok(()) => {
                self.state = DeviceState::Activated { streaming: false };
                Self::one(&self.success())
            }
            Err(e) => self.err_response(e.to_error_code()),
        }
    }

    fn on_sample_request(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        let req = decode_exact::<SampleRequest>(payload)?;
        if !self.is_streaming() {
            // SampleRequest outside the Streaming substate -- per §8
            // the server is expected to see a SampleErrorResponse so
            // it can correlate with the in-flight request.
            return Self::one(&SampleErrorResponse::new(
                self.negotiated_version,
                req.stream_index,
                ErrorCode::NotInitialized,
            ));
        }
        match self.device.capture_sample(req.stream_index) {
            Ok(sample) => {
                // Defence in depth: the `SampleResponse` encoder
                // enforces MAX_SAMPLE_BYTES, but we check here too
                // so a misbehaving host cannot slip a 10 MiB buffer
                // through to `encode_to_vec` where the failure would
                // surface as a channel-level `DvcError::Encode`
                // instead of the spec-mandated `SampleErrorResponse`.
                if sample.len() > crate::pdu::capture::MAX_SAMPLE_BYTES {
                    return Self::one(&SampleErrorResponse::new(
                        self.negotiated_version,
                        req.stream_index,
                        ErrorCode::OutOfMemory,
                    ));
                }
                Self::one(&SampleResponse {
                    version: self.negotiated_version,
                    stream_index: req.stream_index,
                    sample,
                })
            }
            Err(e) => Self::one(&SampleErrorResponse::new(
                self.negotiated_version,
                req.stream_index,
                e.to_error_code(),
            )),
        }
    }

    fn on_property_list(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        decode_exact::<PropertyListRequest>(payload)?;
        if !self.is_activated() {
            return self.err_response(ErrorCode::NotInitialized);
        }
        let resp = PropertyListResponse {
            properties: self.device.property_list().to_vec(),
        };
        Self::one(&resp)
    }

    fn on_property_value(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        let req = decode_exact::<PropertyValueRequest>(payload)?;
        if !self.is_activated() {
            return self.err_response(ErrorCode::NotInitialized);
        }
        match self.device.property_value(req.property_set, req.property_id) {
            Ok(v) => Self::one(&PropertyValueResponse::new(v)),
            Err(e) => self.err_response(e.to_error_code()),
        }
    }

    fn on_set_property_value(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        let req = decode_exact::<SetPropertyValueRequest>(payload)?;
        if !self.is_activated() {
            return self.err_response(ErrorCode::NotInitialized);
        }
        match self
            .device
            .set_property_value(req.property_set, req.property_id, req.value)
        {
            Ok(()) => Self::one(&self.success()),
            Err(e) => self.err_response(e.to_error_code()),
        }
    }

    /// Top-level dispatcher. Returns the messages the processor would
    /// like sent back to the server for a single inbound payload.
    fn dispatch(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        // The shared header is 2 bytes. A payload shorter than that
        // cannot be decoded at all.
        if payload.len() < 2 {
            return self.err_response(ErrorCode::InvalidMessage);
        }
        let version = payload[0];
        let message_id = payload[1];
        // Version must match what was negotiated on the enumerator.
        if version != self.negotiated_version {
            return self.err_response(ErrorCode::InvalidMessage);
        }
        // v2-only messages cannot arrive on a v1 device channel.
        if self.negotiated_version == 1 && is_v2_only(message_id) {
            return self.err_response(ErrorCode::InvalidMessage);
        }
        match message_id {
            MSG_ACTIVATE_DEVICE_REQUEST => self.on_activate(payload),
            MSG_DEACTIVATE_DEVICE_REQUEST => self.on_deactivate(payload),
            MSG_STREAM_LIST_REQUEST => self.on_stream_list(payload),
            MSG_MEDIA_TYPE_LIST_REQUEST => self.on_media_type_list(payload),
            MSG_CURRENT_MEDIA_TYPE_REQUEST => self.on_current_media_type(payload),
            MSG_START_STREAMS_REQUEST => self.on_start_streams(payload),
            MSG_STOP_STREAMS_REQUEST => self.on_stop_streams(payload),
            MSG_SAMPLE_REQUEST => self.on_sample_request(payload),
            MSG_PROPERTY_LIST_REQUEST => self.on_property_list(payload),
            MSG_PROPERTY_VALUE_REQUEST => self.on_property_value(payload),
            MSG_SET_PROPERTY_VALUE_REQUEST => self.on_set_property_value(payload),
            // Includes all C→S-only messages (Success/Error/Sample*) plus
            // genuinely unknown ids.
            _ => self.err_response(ErrorCode::InvalidMessage),
        }
    }
}

/// Decodes exactly `P` from `payload`. Both a parse failure and
/// trailing-byte garbage surface as `DvcError::Decode`, which
/// `process()` catches and translates into
/// `ErrorResponse(InvalidMessage)` per MS-RDPECAM §8. Keeping every
/// wire-format defect in a single error variant is what lets the
/// caller replace the usual `?` with a uniform catch-arm without
/// accidentally letting a `DvcError::Protocol` (channel tear-down)
/// escape for a bug the spec only intends to trigger an error reply.
fn decode_exact<P>(payload: &[u8]) -> DvcResult<P>
where
    for<'a> P: Decode<'a>,
{
    let mut cur = ReadCursor::new(payload);
    let pdu = P::decode(&mut cur).map_err(DvcError::Decode)?;
    if cur.remaining() != 0 {
        return Err(DvcError::Decode(justrdp_core::DecodeError::invalid_value(
            "CAM::device",
            "trailing bytes after PDU",
        )));
    }
    Ok(pdu)
}

impl AsAny for RdpecamDeviceClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl DvcProcessor for RdpecamDeviceClient {
    fn channel_name(&self) -> &str {
        &self.channel_name
    }

    fn start(&mut self, channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        // If DRDYNVC re-creates this channel after an earlier close,
        // we MUST tear the host state down in the same order the
        // per-message handlers do -- stop_streams before deactivate --
        // otherwise a host that enforces the ordering contract would
        // leak a streaming handle every time the DVC bounces. Both
        // teardown calls are best-effort because the trait cannot
        // report errors from within `start()`.
        if self.is_streaming() {
            let _ = self.device.stop_streams();
        }
        if self.is_activated() {
            let _ = self.device.deactivate();
        }
        self.channel_id = channel_id;
        self.state = DeviceState::Initialised;
        Ok(Vec::new())
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if !self.is_open() {
            return Err(DvcError::Protocol(String::from(
                "RDPECAM device: process() outside open lifetime",
            )));
        }
        if channel_id != self.channel_id {
            return Err(DvcError::Protocol(String::from(
                "RDPECAM device: channel_id mismatch",
            )));
        }
        // Every wire-format defect (malformed field, wrong size,
        // trailing bytes) arrives here as `DvcError::Decode` and is
        // answered with `ErrorResponse(InvalidMessage)`. Any other
        // error is a genuine protocol / encoding failure and bubbles
        // up so the DVC framework can tear the channel down.
        match self.dispatch(payload) {
            Ok(msgs) => Ok(msgs),
            Err(DvcError::Decode(_)) => self.err_response(ErrorCode::InvalidMessage),
            Err(other) => Err(other),
        }
    }

    fn close(&mut self, channel_id: u32) {
        if !self.is_open() || channel_id != self.channel_id {
            return;
        }
        // Attempt graceful host teardown, but never propagate failures
        // out of `close()` since the trait signature cannot return them.
        if self.is_streaming() {
            let _ = self.device.stop_streams();
        }
        if self.is_activated() {
            let _ = self.device.deactivate();
        }
        self.state = DeviceState::Closed;
        self.channel_id = 0;
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::camera::{MockCameraDevice, StartStreamInfo};
    use crate::constants::{VERSION_1, VERSION_2};
    use crate::pdu::capture::SampleRequest;
    use crate::pdu::device::{ActivateDeviceRequest, DeactivateDeviceRequest};
    use crate::pdu::property::{
        camera_control_property_id, property_capabilities, video_proc_amp_property_id,
        PropertyDescription, PropertyListRequest, PropertyMode, PropertySet, PropertyValue,
        PropertyValueRequest, PropertyValueResponse, SetPropertyValueRequest,
    };
    use crate::pdu::stream::{
        frame_source_types, media_type_flags, MediaFormat, MediaTypeDescription,
        MediaTypeListRequest, StreamDescription, StreamListRequest, STREAM_CATEGORY_CAPTURE,
    };
    use crate::pdu::capture::{StartStreamsRequest, StopStreamsRequest};

    fn base_media_type() -> MediaTypeDescription {
        MediaTypeDescription {
            format: MediaFormat::H264,
            width: 640,
            height: 480,
            frame_rate_numerator: 30,
            frame_rate_denominator: 1,
            pixel_aspect_ratio_numerator: 1,
            pixel_aspect_ratio_denominator: 1,
            flags: media_type_flags::DECODING_REQUIRED,
        }
    }

    fn base_stream() -> StreamDescription {
        StreamDescription {
            frame_source_types: frame_source_types::COLOR,
            stream_category: STREAM_CATEGORY_CAPTURE,
            selected: 1,
            can_be_shared: 1,
        }
    }

    fn build_client_with_samples(
        version: u8,
        samples: Vec<(u8, Vec<u8>)>,
    ) -> RdpecamDeviceClient {
        let mut device = MockCameraDevice::new()
            .with_stream(base_stream(), alloc::vec![base_media_type()]);
        for (idx, sample) in samples {
            device = device.with_queued_sample(idx, sample);
        }
        let device = device.with_property(
            PropertyDescription {
                property_set: PropertySet::VideoProcAmp,
                property_id: video_proc_amp_property_id::BRIGHTNESS,
                capabilities: property_capabilities::MANUAL,
                min_value: 0,
                max_value: 255,
                step: 1,
                default_value: 128,
            },
            PropertyValue::manual(128),
        );
        RdpecamDeviceClient::new(
            String::from("RDCamera_Device_0"),
            version,
            Box::new(device),
        )
    }

    fn build_client(version: u8) -> RdpecamDeviceClient {
        build_client_with_samples(version, Vec::new())
    }

    /// Encodes a PDU and dispatches it through the processor, asserting
    /// that exactly one response message came back. Returns the response
    /// payload bytes for downstream inspection.
    fn exchange(client: &mut RdpecamDeviceClient, pdu: impl Encode) -> Vec<u8> {
        let bytes = encode_to_vec(&pdu).unwrap();
        let mut out = client.process(1, &bytes).unwrap();
        assert_eq!(out.len(), 1, "expected exactly one response");
        out.remove(0).data
    }

    fn first_two(bytes: &[u8]) -> (u8, u8) {
        (bytes[0], bytes[1])
    }

    // ── Lifecycle ──

    #[test]
    fn start_places_client_in_initialised_state() {
        let mut c = build_client(VERSION_2);
        let msgs = c.start(1).unwrap();
        assert!(msgs.is_empty());
        assert!(c.is_open());
        assert!(!c.is_activated());
        assert!(!c.is_streaming());
    }

    #[test]
    fn process_before_start_errors_as_protocol() {
        let mut c = build_client(VERSION_2);
        let err = c.process(1, &[VERSION_2, MSG_ACTIVATE_DEVICE_REQUEST]).unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn process_rejects_wrong_channel_id() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        let bytes = encode_to_vec(&ActivateDeviceRequest::new(VERSION_2)).unwrap();
        let err = c.process(2, &bytes).unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    // ── Activate / Deactivate ──

    #[test]
    fn activate_happy_path_returns_success_and_transitions() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        let resp = exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        assert_eq!(first_two(&resp), (VERSION_2, 0x01)); // SuccessResponse
        assert!(c.is_activated());
        assert!(!c.is_streaming());
    }

    #[test]
    fn activate_while_already_activated_returns_invalid_request() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        let resp = exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        assert_eq!(first_two(&resp), (VERSION_2, 0x02)); // ErrorResponse
        assert_eq!(
            u32::from_le_bytes([resp[2], resp[3], resp[4], resp[5]]),
            ErrorCode::InvalidRequest.to_u32()
        );
    }

    #[test]
    fn deactivate_before_activate_returns_not_initialized() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        let resp = exchange(&mut c, DeactivateDeviceRequest::new(VERSION_2));
        assert_eq!(first_two(&resp), (VERSION_2, 0x02));
        assert_eq!(
            u32::from_le_bytes([resp[2], resp[3], resp[4], resp[5]]),
            ErrorCode::NotInitialized.to_u32()
        );
    }

    #[test]
    fn deactivate_from_streaming_stops_streams_implicitly() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        exchange(
            &mut c,
            StartStreamsRequest {
                version: VERSION_2,
                infos: alloc::vec![StartStreamInfo {
                    stream_index: 0,
                    media_type: base_media_type(),
                }],
            },
        );
        assert!(c.is_streaming());
        let resp = exchange(&mut c, DeactivateDeviceRequest::new(VERSION_2));
        assert_eq!(first_two(&resp), (VERSION_2, 0x01));
        assert!(!c.is_activated());
        assert!(!c.is_streaming());
        // Behaviour check: after a stream-shutdown-then-deactivate cycle,
        // a fresh activate + start_streams must succeed, which is only
        // possible if the mock's stop_streams + deactivate ran in order.
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        let resp = exchange(
            &mut c,
            StartStreamsRequest {
                version: VERSION_2,
                infos: alloc::vec![StartStreamInfo {
                    stream_index: 0,
                    media_type: base_media_type(),
                }],
            },
        );
        assert_eq!(first_two(&resp), (VERSION_2, 0x01));
    }

    // ── StreamList / MediaType list & current ──

    #[test]
    fn stream_list_happy_path_returns_response() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        let resp = exchange(&mut c, StreamListRequest::new(VERSION_2));
        assert_eq!(first_two(&resp), (VERSION_2, 0x0A));
        // Header + 1 stream * 5 bytes.
        assert_eq!(resp.len(), 2 + 5);
    }

    #[test]
    fn stream_list_before_activate_returns_not_initialized() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        let resp = exchange(&mut c, StreamListRequest::new(VERSION_2));
        assert_eq!(first_two(&resp), (VERSION_2, 0x02));
    }

    #[test]
    fn media_type_list_invalid_stream_index_returns_invalid_stream_number() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        let resp = exchange(&mut c, MediaTypeListRequest::new(VERSION_2, 99));
        assert_eq!(first_two(&resp), (VERSION_2, 0x02));
        assert_eq!(
            u32::from_le_bytes([resp[2], resp[3], resp[4], resp[5]]),
            ErrorCode::InvalidStreamNumber.to_u32()
        );
    }

    #[test]
    fn current_media_type_happy_path() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        let resp = exchange(&mut c, CurrentMediaTypeRequest::new(VERSION_2, 0));
        assert_eq!(first_two(&resp), (VERSION_2, 0x0E));
    }

    // ── Start / Stop streams + SampleRequest ──

    #[test]
    fn start_streams_transitions_and_sample_returns_queued_frame() {
        // Pre-load one sample into the mock before boxing it; this keeps
        // the test from needing a runtime downcast through the trait
        // object inside the processor.
        let mut c =
            build_client_with_samples(VERSION_2, alloc::vec![(0u8, alloc::vec![0x01, 0x02, 0x03])]);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        exchange(
            &mut c,
            StartStreamsRequest {
                version: VERSION_2,
                infos: alloc::vec![StartStreamInfo {
                    stream_index: 0,
                    media_type: base_media_type(),
                }],
            },
        );
        assert!(c.is_streaming());

        let resp = exchange(&mut c, SampleRequest::new(VERSION_2, 0));
        assert_eq!(first_two(&resp), (VERSION_2, 0x12)); // SampleResponse
        assert_eq!(&resp[2..], &[0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn sample_request_before_streaming_returns_sample_error_response() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        let resp = exchange(&mut c, SampleRequest::new(VERSION_2, 0));
        assert_eq!(first_two(&resp), (VERSION_2, 0x13));
        assert_eq!(resp[2], 0); // stream_index
        assert_eq!(
            u32::from_le_bytes([resp[3], resp[4], resp[5], resp[6]]),
            ErrorCode::NotInitialized.to_u32()
        );
    }

    #[test]
    fn sample_request_empty_queue_returns_sample_error_response_with_host_code() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        exchange(
            &mut c,
            StartStreamsRequest {
                version: VERSION_2,
                infos: alloc::vec![StartStreamInfo {
                    stream_index: 0,
                    media_type: base_media_type(),
                }],
            },
        );
        let resp = exchange(&mut c, SampleRequest::new(VERSION_2, 0));
        assert_eq!(first_two(&resp), (VERSION_2, 0x13));
        assert_eq!(
            u32::from_le_bytes([resp[3], resp[4], resp[5], resp[6]]),
            ErrorCode::InvalidRequest.to_u32()
        );
    }

    #[test]
    fn stop_streams_before_streaming_returns_not_initialized() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        let resp = exchange(&mut c, StopStreamsRequest::new(VERSION_2));
        assert_eq!(first_two(&resp), (VERSION_2, 0x02));
    }

    #[test]
    fn stop_streams_happy_path_transitions_back_to_activated() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        exchange(
            &mut c,
            StartStreamsRequest {
                version: VERSION_2,
                infos: alloc::vec![StartStreamInfo {
                    stream_index: 0,
                    media_type: base_media_type(),
                }],
            },
        );
        let resp = exchange(&mut c, StopStreamsRequest::new(VERSION_2));
        assert_eq!(first_two(&resp), (VERSION_2, 0x01));
        assert!(c.is_activated());
        assert!(!c.is_streaming());
    }

    // ── Property API (v2) ──

    #[test]
    fn property_list_on_v2_returns_description() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        let resp = exchange(&mut c, PropertyListRequest);
        assert_eq!(first_two(&resp), (VERSION_2, 0x15));
        // 1 property description = 2 header + 19.
        assert_eq!(resp.len(), 2 + 19);
    }

    #[test]
    fn property_value_roundtrip_on_v2() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));

        let resp_bytes = exchange(
            &mut c,
            PropertyValueRequest::new(
                PropertySet::VideoProcAmp,
                video_proc_amp_property_id::BRIGHTNESS,
            ),
        );
        let mut cur = ReadCursor::new(&resp_bytes);
        let resp = PropertyValueResponse::decode(&mut cur).unwrap();
        assert_eq!(resp.value.mode, PropertyMode::Manual);
        assert_eq!(resp.value.value, 128);

        // Set new value, then read back.
        let resp_bytes = exchange(
            &mut c,
            SetPropertyValueRequest::new(
                PropertySet::VideoProcAmp,
                video_proc_amp_property_id::BRIGHTNESS,
                PropertyValue::manual(200),
            ),
        );
        assert_eq!(first_two(&resp_bytes), (VERSION_2, 0x01));

        let resp_bytes = exchange(
            &mut c,
            PropertyValueRequest::new(
                PropertySet::VideoProcAmp,
                video_proc_amp_property_id::BRIGHTNESS,
            ),
        );
        let mut cur = ReadCursor::new(&resp_bytes);
        let resp = PropertyValueResponse::decode(&mut cur).unwrap();
        assert_eq!(resp.value.value, 200);
    }

    #[test]
    fn property_value_unknown_id_returns_item_not_found() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        let resp = exchange(
            &mut c,
            PropertyValueRequest::new(
                PropertySet::CameraControl,
                camera_control_property_id::ZOOM,
            ),
        );
        assert_eq!(first_two(&resp), (VERSION_2, 0x02));
        assert_eq!(
            u32::from_le_bytes([resp[2], resp[3], resp[4], resp[5]]),
            ErrorCode::ItemNotFound.to_u32()
        );
    }

    // ── v1-specific paths ──

    #[test]
    fn v1_channel_rejects_v2_only_message_id() {
        let mut c = build_client(VERSION_1);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_1));
        // Craft a PropertyListRequest with Version=1 -- this is a
        // synthetic wire vector because our encoder hardwires v2.
        let bytes = [VERSION_1, MSG_PROPERTY_LIST_REQUEST];
        let mut out = c.process(1, &bytes).unwrap();
        let resp = out.remove(0).data;
        assert_eq!(first_two(&resp), (VERSION_1, 0x02));
        assert_eq!(
            u32::from_le_bytes([resp[2], resp[3], resp[4], resp[5]]),
            ErrorCode::InvalidMessage.to_u32()
        );
    }

    // ── Dispatch error paths ──

    #[test]
    fn short_payload_returns_invalid_message() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        let mut out = c.process(1, &[0x02]).unwrap();
        let resp = out.remove(0).data;
        assert_eq!(first_two(&resp), (VERSION_2, 0x02));
        assert_eq!(
            u32::from_le_bytes([resp[2], resp[3], resp[4], resp[5]]),
            ErrorCode::InvalidMessage.to_u32()
        );
    }

    #[test]
    fn wrong_version_byte_returns_invalid_message() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        let mut out = c
            .process(1, &[VERSION_1, MSG_ACTIVATE_DEVICE_REQUEST])
            .unwrap();
        let resp = out.remove(0).data;
        assert_eq!(first_two(&resp), (VERSION_2, 0x02));
    }

    #[test]
    fn unknown_message_id_returns_invalid_message() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        let mut out = c.process(1, &[VERSION_2, 0xEF]).unwrap();
        let resp = out.remove(0).data;
        assert_eq!(first_two(&resp), (VERSION_2, 0x02));
    }

    #[test]
    fn server_sending_client_only_message_returns_invalid_message() {
        // Every MessageId that is C→S-only on the device channel
        // MUST produce `ErrorResponse(InvalidMessage)` when arriving
        // from the server. Covers SuccessResponse (0x01),
        // ErrorResponse (0x02), SampleResponse (0x12), and
        // SampleErrorResponse (0x13) to lock in the contract for the
        // whole set, not just the canonical 0x01 case.
        for id in [0x01u8, 0x02, 0x12, 0x13] {
            let mut c = build_client(VERSION_2);
            c.start(1).unwrap();
            let mut out = c.process(1, &[VERSION_2, id]).unwrap();
            let resp = out.remove(0).data;
            assert_eq!(
                first_two(&resp),
                (VERSION_2, 0x02),
                "message id 0x{:02x} should be rejected",
                id
            );
            assert_eq!(
                u32::from_le_bytes([resp[2], resp[3], resp[4], resp[5]]),
                ErrorCode::InvalidMessage.to_u32()
            );
        }
    }

    #[test]
    fn trailing_bytes_after_valid_pdu_return_invalid_message() {
        // A wire-format defect that `Decode` itself does not surface
        // (the PDU parsed, there were just extra trailing bytes)
        // MUST still be answered with `ErrorResponse(InvalidMessage)`
        // rather than escaping as a channel-level `DvcError::Protocol`
        // that tears the DVC down. Regression guard for the Step 5
        // review fix of `decode_exact`.
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        // Encode a valid ActivateDeviceRequest and append one byte.
        let mut bytes = encode_to_vec(&ActivateDeviceRequest::new(VERSION_2)).unwrap();
        bytes.push(0xFF);
        let mut out = c.process(1, &bytes).unwrap();
        let resp = out.remove(0).data;
        assert_eq!(first_two(&resp), (VERSION_2, 0x02));
        assert_eq!(
            u32::from_le_bytes([resp[2], resp[3], resp[4], resp[5]]),
            ErrorCode::InvalidMessage.to_u32()
        );
        // And the processor is still healthy: a subsequent well-formed
        // Activate must still succeed.
        let ok = exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        assert_eq!(first_two(&ok), (VERSION_2, 0x01));
    }

    #[test]
    fn start_recreate_during_streaming_tears_down_in_order() {
        // Simulates DRDYNVC re-creating the per-device channel while
        // the host is mid-stream. The processor MUST call
        // `stop_streams` before `deactivate`, never the other way
        // round, so a host that enforces the ordering does not leak a
        // streaming handle. After the second `start()` the processor
        // must be back in `Initialised` and a fresh Activate must
        // work against the same (re-armed) mock.
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        exchange(
            &mut c,
            StartStreamsRequest {
                version: VERSION_2,
                infos: alloc::vec![StartStreamInfo {
                    stream_index: 0,
                    media_type: base_media_type(),
                }],
            },
        );
        assert!(c.is_streaming());
        // Server tears down and re-creates (same channel id so the
        // in-process `exchange` helper keeps working). Internally
        // this MUST call stop_streams then deactivate on the host
        // trait before resetting local state.
        c.start(1).unwrap();
        assert!(c.is_open());
        assert!(!c.is_activated());
        assert!(!c.is_streaming());
        // The mock accepts a fresh activate/start cycle only if the
        // prior teardown left it consistent (not half-streaming).
        let ok = exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        assert_eq!(first_two(&ok), (VERSION_2, 0x01));
        let ok = exchange(
            &mut c,
            StartStreamsRequest {
                version: VERSION_2,
                infos: alloc::vec![StartStreamInfo {
                    stream_index: 0,
                    media_type: base_media_type(),
                }],
            },
        );
        assert_eq!(first_two(&ok), (VERSION_2, 0x01));
    }

    #[test]
    fn close_resets_lifecycle_state_and_ignores_wrong_channel_id() {
        let mut c = build_client(VERSION_2);
        c.start(1).unwrap();
        exchange(&mut c, ActivateDeviceRequest::new(VERSION_2));
        exchange(
            &mut c,
            StartStreamsRequest {
                version: VERSION_2,
                infos: alloc::vec![StartStreamInfo {
                    stream_index: 0,
                    media_type: base_media_type(),
                }],
            },
        );
        // Wrong channel -- no-op.
        c.close(99);
        assert!(c.is_open());
        assert!(c.is_streaming());
        // Correct channel -- fully closes.
        c.close(1);
        assert!(!c.is_open());
        assert!(!c.is_activated());
        assert!(!c.is_streaming());
    }
}
