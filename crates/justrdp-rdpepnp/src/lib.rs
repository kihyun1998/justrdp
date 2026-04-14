#![no_std]
#![forbid(unsafe_code)]

//! Plug and Play Device Redirection Virtual Channel Extension -- MS-RDPEPNP
//!
//! MS-RDPEPNP defines two independent dynamic virtual channel sub-protocols:
//!
//! 1. **PNP Device Info** (`"PNPDR"`) — the control channel that negotiates
//!    version, waits for authentication, then announces and removes client
//!    PnP devices (§9.14a). Entry point: [`PnpInfoClient`].
//! 2. **PNP Device I/O** (`"FileRedirectorChannel"`, multi-instance) — the
//!    per-file I/O sub-protocol carrying CreateFile / Read / Write /
//!    IoControl / IoCancel and custom events (§9.14b). Entry point:
//!    [`FileRedirectorChannelClient`].
//!
//! Each `PNPDR` message shares a fixed 8-byte [`PnpInfoHeader`] with a `Size`
//! field (total PDU size including the header, little-endian) and a
//! `PacketId` discriminator. All multi-byte fields are little-endian.
//!
//! ## PDU catalog (PNPDR, §2.2.1)
//!
//! | PacketId | Name                            | Direction | Size (bytes)           |
//! | -------- | ------------------------------- | --------- | ---------------------- |
//! | `0x0065` | Server / Client Version Message | S→C / C→S | 20 (fixed)             |
//! | `0x0067` | Authenticated Client Message    | S→C       | 8 (header only)        |
//! | `0x0066` | Client Device Addition Message  | C→S       | 12 + Σ PnpDeviceDesc   |
//! | `0x0068` | Client Device Removal Message   | C→S       | 12 (fixed)             |
//!
//! ## Modules
//!
//! - [`constants`] — wire constants (PacketIds, capability bits, CustomFlag, DeviceCaps)
//! - [`pdu`] — wire-format structs and encode/decode implementations
//! - [`client`] — [`PnpInfoClient`] DVC processor and associated state

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod constants;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
pub mod client;

#[cfg(feature = "alloc")]
pub mod file_redirector;

pub use constants::{
    function_id, io_version, packet_id, packet_type, CLIENT_IO_HEADER_SIZE,
    FILE_REDIRECTOR_CHANNEL_NAME, MAX_CUSTOM_EVENT_BYTES, MAX_DEVICES,
    MAX_DEVICE_DESCRIPTION_BYTES, MAX_HARDWARE_ID_BYTES, MAX_INTERFACE_BYTES,
    MAX_IOCONTROL_BYTES, MAX_OUTSTANDING_REQUESTS, MAX_READ_BYTES, MAX_REQUEST_ID, MAX_WRITE_BYTES,
    PNPDR_CHANNEL_NAME, PNP_CAP_DYNAMIC_DEVICE_ADDITION, PNP_INFO_HEADER_SIZE,
    SERVER_IO_HEADER_SIZE,
};

#[cfg(feature = "alloc")]
pub use pdu::{
    AuthenticatedClientMsg, ClientCapabilitiesReply, ClientDeviceAdditionMsg,
    ClientDeviceCustomEvent, ClientDeviceRemovalMsg, ClientIoHeader, ClientVersionMsg,
    CreateFileReply, CreateFileRequest, IoControlReply, IoControlRequest, PnpDeviceDescription,
    PnpInfoHeader, ReadReply, ReadRequest, ServerCapabilitiesRequest, ServerIoHeader,
    ServerVersionMsg, SpecificIoCancelRequest, VersionMsg, WriteReply, WriteRequest,
};

#[cfg(feature = "alloc")]
pub use client::{
    DeviceEntry, NullCallback, PnpInfoCallback, PnpInfoClient, PnpInfoError, PnpInfoState,
};

#[cfg(feature = "alloc")]
pub use file_redirector::{
    ChannelInstance, FileRedirectorChannelClient, FileRedirectorError, FileRedirectorState,
    IoCallback, IoRequestKind, NullIoCallback, E_NOTIMPL,
};

#[cfg(all(test, feature = "alloc"))]
mod client_tests;

#[cfg(all(test, feature = "alloc"))]
mod pdu_tests;

#[cfg(all(test, feature = "alloc"))]
mod pdu_io_tests;

#[cfg(all(test, feature = "alloc"))]
mod file_redirector_tests;
