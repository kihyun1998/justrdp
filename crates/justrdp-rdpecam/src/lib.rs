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
//! the embedder supplies frames through the [`camera::CameraHost`] trait.
//!
//! Module layout (see `specs/ms-rdpecam-checklist.md`):
//!
//! - [`constants`] -- message ids, enums, property sets, error codes
//! - [`pdu`]       -- wire-format structs grouped by message family
//! - [`camera`]    -- `CameraHost` trait (frame source + property backend)
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
