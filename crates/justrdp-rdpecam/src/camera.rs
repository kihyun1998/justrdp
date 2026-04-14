//! [`CameraDevice`] -- the host trait that a single camera surface
//! implements so the DVC processors can drive it without knowing
//! anything about the underlying OS capture API.
//!
//! The trait is deliberately *blocking*: `capture_sample` may stall the
//! caller for the duration of a hardware grab, and the embedder is
//! expected to run the per-device [`crate::device::RdpecamDeviceClient`]
//! on its own thread (or inside a runtime task that tolerates blocking)
//! if real hardware is behind it. This matches the protocol's pull
//! model -- the server issues exactly one `SampleRequest` at a time and
//! waits for the matching response -- and keeps the trait usable in
//! `no_std` contexts where there is no executor to await on.

use alloc::vec::Vec;

use crate::constants::ErrorCode;
use crate::pdu::property::{PropertyDescription, PropertySet, PropertyValue};
use crate::pdu::stream::{MediaTypeDescription, StreamDescription};

/// Error type returned by [`CameraDevice`] implementations.
///
/// Every variant maps 1:1 to a wire-level MS-RDPECAM `ErrorCode`, so the
/// processor can forward the failure back to the server without having
/// to translate. Use [`CamError::to_error_code`] at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CamError {
    /// Host does not currently hold the device (not yet activated, or a
    /// deactivate race is in flight).
    NotInitialized,
    /// Caller asked for a stream index that does not exist.
    InvalidStreamNumber,
    /// Media type is malformed or unsupported by the device.
    InvalidMediaType,
    /// Request references a property set or id that does not exist.
    InvalidRequest,
    /// Property set (`PropertySet::Other(..)` or an unknown set).
    SetNotFound,
    /// Property id does not exist inside the given set.
    ItemNotFound,
    /// Host refuses to perform the operation (e.g. set a read-only
    /// property, or engage a mode the device does not support).
    OperationNotSupported,
    /// Client-side allocation failure while preparing the response.
    OutOfMemory,
    /// Catch-all for host-side bugs the embedder cannot classify.
    UnexpectedError,
}

impl CamError {
    /// Returns the wire `ErrorCode` this host error maps to.
    pub fn to_error_code(self) -> ErrorCode {
        match self {
            Self::NotInitialized => ErrorCode::NotInitialized,
            Self::InvalidStreamNumber => ErrorCode::InvalidStreamNumber,
            Self::InvalidMediaType => ErrorCode::InvalidMediaType,
            Self::InvalidRequest => ErrorCode::InvalidRequest,
            Self::SetNotFound => ErrorCode::SetNotFound,
            Self::ItemNotFound => ErrorCode::ItemNotFound,
            Self::OperationNotSupported => ErrorCode::OperationNotSupported,
            Self::OutOfMemory => ErrorCode::OutOfMemory,
            Self::UnexpectedError => ErrorCode::UnexpectedError,
        }
    }
}

/// Host-supplied camera surface for one camera device.
///
/// The processor calls into this trait synchronously on the DVC thread.
/// Implementations may block inside [`Self::capture_sample`] for the
/// duration of a hardware grab; they MUST NOT panic.
///
/// Method semantics mirror the MS-RDPECAM wire protocol: the processor
/// converts each server request into a call on this trait, translates
/// the return value into the appropriate PDU, and hands the response
/// back to `justrdp-dvc`.
pub trait CameraDevice: Send {
    /// Called after the server sends `ActivateDeviceRequest`. The host
    /// should acquire the physical device and enter a state where
    /// [`Self::stream_list`] returns a stable list.
    fn activate(&mut self) -> Result<(), CamError>;

    /// Called after the server sends `DeactivateDeviceRequest`. After
    /// this returns, every other method may be called again only after a
    /// subsequent [`Self::activate`] succeeds.
    fn deactivate(&mut self) -> Result<(), CamError>;

    /// Returns the list of streams offered by this device. The 0-based
    /// position in the returned slice is the stream index that all
    /// later PDUs reference.
    fn stream_list(&self) -> &[StreamDescription];

    /// Returns every media type supported by the given stream. Must
    /// return `InvalidStreamNumber` for unknown indices.
    fn media_type_list(&self, stream_index: u8) -> Result<&[MediaTypeDescription], CamError>;

    /// Returns the media type the stream would produce right now.
    fn current_media_type(&self, stream_index: u8) -> Result<MediaTypeDescription, CamError>;

    /// Starts producing frames for the listed streams. Each entry pairs
    /// a stream index with the exact media type the server wants.
    fn start_streams(&mut self, infos: &[StartStreamInfo]) -> Result<(), CamError>;

    /// Stops every stream on this device. Mirrors `StopStreamsRequest`
    /// which has no per-stream selection.
    fn stop_streams(&mut self) -> Result<(), CamError>;

    /// Captures one sample from the given stream. Returns the raw codec
    /// payload to be wrapped in a `SampleResponse`. Empty vectors are
    /// allowed (zero-length sample).
    fn capture_sample(&mut self, stream_index: u8) -> Result<Vec<u8>, CamError>;

    // ── v2 Property API ──

    /// Returns the device's full property list. Default impl returns
    /// an empty slice so v1-only hosts do not have to implement this.
    fn property_list(&self) -> &[PropertyDescription] {
        &[]
    }

    /// Reads one property value. Default impl rejects every request so
    /// a v1-only host cleanly refuses v2 traffic it shouldn't have
    /// received in the first place.
    fn property_value(
        &self,
        _set: PropertySet,
        _id: u8,
    ) -> Result<PropertyValue, CamError> {
        Err(CamError::OperationNotSupported)
    }

    /// Writes one property value. Default impl rejects every request;
    /// see [`Self::property_value`].
    fn set_property_value(
        &mut self,
        _set: PropertySet,
        _id: u8,
        _value: PropertyValue,
    ) -> Result<(), CamError> {
        Err(CamError::OperationNotSupported)
    }
}

// Re-export so trait users don't need a separate import path.
pub use crate::pdu::capture::StartStreamInfo;

// ── MockCameraDevice ──
//
// A deterministic in-memory `CameraDevice` used by the processor tests
// and by anyone embedding the crate who wants a placeholder. It is
// feature-gated behind `alloc` via the module file itself.

/// In-memory test double implementing [`CameraDevice`].
///
/// Behaviour:
///
/// - `activate` / `deactivate` toggle an `is_active` flag; each method
///   returns `NotInitialized` if the state is wrong.
/// - `stream_list` returns a fixed slice configured at construction.
/// - `capture_sample` returns the pre-queued frame for the given stream,
///   or `InvalidRequest` if the queue is empty.
/// - `property_value` / `set_property_value` manipulate an in-memory map
///   so the v2 API can be exercised end-to-end.
#[derive(Debug, Default)]
pub struct MockCameraDevice {
    streams: Vec<StreamDescription>,
    media_types: Vec<Vec<MediaTypeDescription>>,
    current_types: Vec<Option<MediaTypeDescription>>,
    properties: Vec<PropertyDescription>,
    property_values: Vec<((u8, u8), PropertyValue)>,
    pending_samples: Vec<Vec<Vec<u8>>>,
    is_active: bool,
    is_streaming: bool,
    pub activate_calls: u32,
    pub deactivate_calls: u32,
    pub start_streams_calls: u32,
    pub stop_streams_calls: u32,
}

impl MockCameraDevice {
    /// Constructs an empty mock with no streams. Builder methods add state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one stream together with its media type list and initial
    /// "current" media type (the first entry of the list).
    pub fn with_stream(
        mut self,
        stream: StreamDescription,
        media_types: Vec<MediaTypeDescription>,
    ) -> Self {
        let current = media_types.first().copied();
        self.streams.push(stream);
        self.media_types.push(media_types);
        self.current_types.push(current);
        self.pending_samples.push(Vec::new());
        self
    }

    /// Adds a property description and its initial value.
    pub fn with_property(
        mut self,
        desc: PropertyDescription,
        value: PropertyValue,
    ) -> Self {
        let key = (desc.property_set.to_u8(), desc.property_id);
        self.properties.push(desc);
        self.property_values.push((key, value));
        self
    }

    /// Queues a sample to be returned by the next
    /// [`CameraDevice::capture_sample`] call for `stream_index`.
    pub fn push_sample(&mut self, stream_index: u8, sample: Vec<u8>) {
        if let Some(q) = self.pending_samples.get_mut(stream_index as usize) {
            q.push(sample);
        }
    }

    /// Builder-style variant of [`Self::push_sample`] so tests can
    /// pre-load the queue before handing the mock off to a processor
    /// as `Box<dyn CameraDevice>`.
    pub fn with_queued_sample(mut self, stream_index: u8, sample: Vec<u8>) -> Self {
        self.push_sample(stream_index, sample);
        self
    }

    /// True iff [`CameraDevice::activate`] has been called without a
    /// matching [`CameraDevice::deactivate`].
    pub fn is_active(&self) -> bool {
        self.is_active
    }

    /// True iff [`CameraDevice::start_streams`] has been called without a
    /// matching [`CameraDevice::stop_streams`].
    pub fn is_streaming(&self) -> bool {
        self.is_streaming
    }
}

impl CameraDevice for MockCameraDevice {
    fn activate(&mut self) -> Result<(), CamError> {
        if self.is_active {
            return Err(CamError::InvalidRequest);
        }
        self.is_active = true;
        self.activate_calls += 1;
        Ok(())
    }

    fn deactivate(&mut self) -> Result<(), CamError> {
        if !self.is_active {
            return Err(CamError::NotInitialized);
        }
        self.is_active = false;
        self.is_streaming = false;
        self.deactivate_calls += 1;
        Ok(())
    }

    fn stream_list(&self) -> &[StreamDescription] {
        &self.streams
    }

    fn media_type_list(&self, stream_index: u8) -> Result<&[MediaTypeDescription], CamError> {
        self.media_types
            .get(stream_index as usize)
            .map(|v| v.as_slice())
            .ok_or(CamError::InvalidStreamNumber)
    }

    fn current_media_type(&self, stream_index: u8) -> Result<MediaTypeDescription, CamError> {
        self.current_types
            .get(stream_index as usize)
            .and_then(|v| *v)
            .ok_or(CamError::InvalidStreamNumber)
    }

    fn start_streams(&mut self, infos: &[StartStreamInfo]) -> Result<(), CamError> {
        if !self.is_active {
            return Err(CamError::NotInitialized);
        }
        for info in infos {
            let idx = info.stream_index as usize;
            if idx >= self.current_types.len() {
                return Err(CamError::InvalidStreamNumber);
            }
            self.current_types[idx] = Some(info.media_type);
        }
        self.is_streaming = true;
        self.start_streams_calls += 1;
        Ok(())
    }

    fn stop_streams(&mut self) -> Result<(), CamError> {
        if !self.is_active {
            return Err(CamError::NotInitialized);
        }
        self.is_streaming = false;
        self.stop_streams_calls += 1;
        Ok(())
    }

    fn capture_sample(&mut self, stream_index: u8) -> Result<Vec<u8>, CamError> {
        if !self.is_streaming {
            return Err(CamError::NotInitialized);
        }
        let q = self
            .pending_samples
            .get_mut(stream_index as usize)
            .ok_or(CamError::InvalidStreamNumber)?;
        if q.is_empty() {
            return Err(CamError::InvalidRequest);
        }
        Ok(q.remove(0))
    }

    fn property_list(&self) -> &[PropertyDescription] {
        &self.properties
    }

    fn property_value(
        &self,
        set: PropertySet,
        id: u8,
    ) -> Result<PropertyValue, CamError> {
        let key = (set.to_u8(), id);
        self.property_values
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| *v)
            .ok_or(CamError::ItemNotFound)
    }

    fn set_property_value(
        &mut self,
        set: PropertySet,
        id: u8,
        value: PropertyValue,
    ) -> Result<(), CamError> {
        let key = (set.to_u8(), id);
        if let Some(slot) = self.property_values.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
            Ok(())
        } else {
            Err(CamError::ItemNotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::property::{
        camera_control_property_id, property_capabilities, video_proc_amp_property_id,
    };
    use crate::pdu::stream::{
        frame_source_types, media_type_flags, MediaFormat, STREAM_CATEGORY_CAPTURE,
    };

    fn sample_stream() -> StreamDescription {
        StreamDescription {
            frame_source_types: frame_source_types::COLOR,
            stream_category: STREAM_CATEGORY_CAPTURE,
            selected: 1,
            can_be_shared: 1,
        }
    }

    fn sample_media_type() -> MediaTypeDescription {
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

    #[test]
    fn mock_lifecycle_happy_path() {
        let mut dev = MockCameraDevice::new()
            .with_stream(sample_stream(), alloc::vec![sample_media_type()]);
        assert!(dev.activate().is_ok());
        assert!(dev.is_active());
        assert_eq!(
            dev.stream_list().len(),
            1,
            "stream_list must reflect the builder state",
        );
        let mt = dev.current_media_type(0).unwrap();
        assert_eq!(mt.width, 640);
        let infos = alloc::vec![StartStreamInfo {
            stream_index: 0,
            media_type: mt,
        }];
        assert!(dev.start_streams(&infos).is_ok());
        assert!(dev.is_streaming());
        dev.push_sample(0, alloc::vec![0x01, 0x02, 0x03]);
        assert_eq!(dev.capture_sample(0).unwrap(), alloc::vec![0x01, 0x02, 0x03]);
        assert!(dev.stop_streams().is_ok());
        assert!(!dev.is_streaming());
        assert!(dev.deactivate().is_ok());
        assert!(!dev.is_active());
    }

    #[test]
    fn mock_rejects_stream_ops_before_activate() {
        let mut dev = MockCameraDevice::new()
            .with_stream(sample_stream(), alloc::vec![sample_media_type()]);
        assert_eq!(
            dev.start_streams(&[]).unwrap_err(),
            CamError::NotInitialized
        );
        assert_eq!(
            dev.stop_streams().unwrap_err(),
            CamError::NotInitialized
        );
        assert_eq!(
            dev.capture_sample(0).unwrap_err(),
            CamError::NotInitialized
        );
    }

    #[test]
    fn mock_rejects_double_activate() {
        let mut dev = MockCameraDevice::new();
        dev.activate().unwrap();
        assert_eq!(dev.activate().unwrap_err(), CamError::InvalidRequest);
    }

    #[test]
    fn mock_rejects_capture_from_empty_queue() {
        let mut dev = MockCameraDevice::new()
            .with_stream(sample_stream(), alloc::vec![sample_media_type()]);
        dev.activate().unwrap();
        dev.start_streams(&[StartStreamInfo {
            stream_index: 0,
            media_type: sample_media_type(),
        }])
        .unwrap();
        assert_eq!(
            dev.capture_sample(0).unwrap_err(),
            CamError::InvalidRequest
        );
    }

    #[test]
    fn mock_capture_from_unknown_stream_index() {
        let mut dev = MockCameraDevice::new()
            .with_stream(sample_stream(), alloc::vec![sample_media_type()]);
        dev.activate().unwrap();
        dev.start_streams(&[StartStreamInfo {
            stream_index: 0,
            media_type: sample_media_type(),
        }])
        .unwrap();
        assert_eq!(
            dev.capture_sample(99).unwrap_err(),
            CamError::InvalidStreamNumber
        );
    }

    #[test]
    fn mock_property_get_set_roundtrip() {
        let desc = PropertyDescription {
            property_set: PropertySet::VideoProcAmp,
            property_id: video_proc_amp_property_id::BRIGHTNESS,
            capabilities: property_capabilities::MANUAL,
            min_value: 0,
            max_value: 255,
            step: 1,
            default_value: 128,
        };
        let initial = PropertyValue::manual(128);
        let mut dev = MockCameraDevice::new().with_property(desc, initial);
        assert_eq!(dev.property_list().len(), 1);
        assert_eq!(
            dev.property_value(
                PropertySet::VideoProcAmp,
                video_proc_amp_property_id::BRIGHTNESS
            )
            .unwrap(),
            initial
        );
        let new_value = PropertyValue::manual(64);
        dev.set_property_value(
            PropertySet::VideoProcAmp,
            video_proc_amp_property_id::BRIGHTNESS,
            new_value,
        )
        .unwrap();
        assert_eq!(
            dev.property_value(
                PropertySet::VideoProcAmp,
                video_proc_amp_property_id::BRIGHTNESS
            )
            .unwrap(),
            new_value
        );
    }

    #[test]
    fn mock_property_value_unknown_id_returns_item_not_found() {
        let dev = MockCameraDevice::new();
        assert_eq!(
            dev.property_value(PropertySet::CameraControl, camera_control_property_id::ZOOM)
                .unwrap_err(),
            CamError::ItemNotFound
        );
    }

    #[test]
    fn default_property_impls_refuse_v2_traffic() {
        // A trivial impl that forwards everything to defaults.
        struct V1Only;
        impl CameraDevice for V1Only {
            fn activate(&mut self) -> Result<(), CamError> {
                Ok(())
            }
            fn deactivate(&mut self) -> Result<(), CamError> {
                Ok(())
            }
            fn stream_list(&self) -> &[StreamDescription] {
                &[]
            }
            fn media_type_list(
                &self,
                _: u8,
            ) -> Result<&[MediaTypeDescription], CamError> {
                Ok(&[])
            }
            fn current_media_type(&self, _: u8) -> Result<MediaTypeDescription, CamError> {
                Err(CamError::InvalidStreamNumber)
            }
            fn start_streams(&mut self, _: &[StartStreamInfo]) -> Result<(), CamError> {
                Ok(())
            }
            fn stop_streams(&mut self) -> Result<(), CamError> {
                Ok(())
            }
            fn capture_sample(&mut self, _: u8) -> Result<Vec<u8>, CamError> {
                Ok(Vec::new())
            }
        }
        let mut dev = V1Only;
        assert!(dev.property_list().is_empty());
        assert_eq!(
            dev.property_value(PropertySet::CameraControl, 0x01)
                .unwrap_err(),
            CamError::OperationNotSupported
        );
        assert_eq!(
            dev.set_property_value(
                PropertySet::CameraControl,
                0x01,
                PropertyValue::manual(0)
            )
            .unwrap_err(),
            CamError::OperationNotSupported
        );
    }

    #[test]
    fn cam_error_to_error_code_mapping() {
        assert_eq!(
            CamError::NotInitialized.to_error_code(),
            ErrorCode::NotInitialized
        );
        assert_eq!(
            CamError::InvalidStreamNumber.to_error_code(),
            ErrorCode::InvalidStreamNumber
        );
        assert_eq!(
            CamError::ItemNotFound.to_error_code(),
            ErrorCode::ItemNotFound
        );
        assert_eq!(
            CamError::SetNotFound.to_error_code(),
            ErrorCode::SetNotFound
        );
        assert_eq!(
            CamError::OperationNotSupported.to_error_code(),
            ErrorCode::OperationNotSupported
        );
    }
}
