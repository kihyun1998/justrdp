#![no_std]
#![forbid(unsafe_code)]

//! Video Capture (Camera) Virtual Channel Extension -- MS-RDPECAM
//!
//! Client-to-server camera device redirection over DVC. The server opens a
//! fixed enumeration channel (`RDCamera_Device_Enumerator`) used to negotiate
//! the protocol version and discover attached camera devices; each added
//! device advertises a dynamically named per-device channel that carries
//! stream enumeration, media type negotiation, property control, and sample
//! delivery (client → server).
//!
//! Unlike MS-RDPEVOR (§9.8), where the server pushes encoded video to the
//! client, RDPECAM flows from client camera hardware up to a server-side
//! consumer. Raw codec payloads are passed through as opaque byte slices;
//! the embedder supplies frames through the [`camera::CameraDevice`] trait.
//!
//! Module layout (see `specs/ms-rdpecam-checklist.md`):
//!
//! - [`constants`] -- message ids, enums, property sets, error codes
//! - [`pdu`]       -- wire-format structs grouped by message family
//! - [`camera`]    -- `CameraDevice` trait (frame source + property backend)
//! - [`enumerator`] -- `RdpecamEnumeratorClient` DVC processor (version + device discovery)
//! - [`device`]    -- `RdpecamDeviceClient` DVC processor (per-device streaming)

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod constants;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
pub mod camera;

#[cfg(feature = "alloc")]
pub mod enumerator;

#[cfg(feature = "alloc")]
pub mod device;

/// Null-terminated ANSI name of the fixed device enumeration DVC (MS-RDPECAM §2.1).
pub const ENUMERATOR_CHANNEL_NAME: &str = "RDCamera_Device_Enumerator";

// ── Public re-exports ──

pub use constants::{ErrorCode, VERSION_1, VERSION_2};

#[cfg(feature = "alloc")]
pub use camera::{CamError, CameraDevice, MockCameraDevice, StartStreamInfo};

#[cfg(feature = "alloc")]
pub use enumerator::{
    AnnouncedDevice, RdpecamEnumeratorBuilder, RdpecamEnumeratorClient,
};

#[cfg(feature = "alloc")]
pub use device::RdpecamDeviceClient;

#[cfg(feature = "alloc")]
pub use pdu::capture::{
    SampleErrorResponse, SampleRequest, SampleResponse, StartStreamsRequest, StopStreamsRequest,
};

#[cfg(feature = "alloc")]
pub use pdu::device::{
    ActivateDeviceRequest, DeactivateDeviceRequest, ErrorResponse, SuccessResponse,
};

#[cfg(feature = "alloc")]
pub use pdu::enumeration::{
    DeviceAddedNotification, DeviceRemovedNotification, SelectVersionRequest,
    SelectVersionResponse,
};

#[cfg(feature = "alloc")]
pub use pdu::property::{
    camera_control_property_id, property_capabilities, video_proc_amp_property_id,
    PropertyDescription, PropertyListRequest, PropertyListResponse, PropertyMode, PropertySet,
    PropertyValue, PropertyValueRequest, PropertyValueResponse, SetPropertyValueRequest,
};

#[cfg(feature = "alloc")]
pub use pdu::stream::{
    frame_source_types, media_type_flags, CurrentMediaTypeRequest, CurrentMediaTypeResponse,
    MediaFormat, MediaTypeDescription, MediaTypeListRequest, MediaTypeListResponse,
    StreamDescription, StreamListRequest, StreamListResponse, STREAM_CATEGORY_CAPTURE,
};
