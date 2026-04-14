#![no_std]
#![forbid(unsafe_code)]

//! Plug and Play Device Redirection Virtual Channel Extension -- MS-RDPEPNP
//!
//! MS-RDPEPNP defines two independent dynamic virtual channel sub-protocols:
//!
//! 1. **PNP Device Info** (`"PNPDR"`) — the control channel that negotiates
//!    version, waits for authentication, then announces and removes client
//!    PnP devices. Implemented in this step (§9.14a).
//! 2. **PNP Device I/O** (`"FileRedirectorChannel"`, multi-instance) — the
//!    per-file I/O sub-protocol. Deferred to §9.14b.
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

pub use constants::{
    packet_id, MAX_DEVICES, MAX_DEVICE_DESCRIPTION_BYTES, MAX_HARDWARE_ID_BYTES,
    MAX_INTERFACE_BYTES, PNPDR_CHANNEL_NAME, PNP_CAP_DYNAMIC_DEVICE_ADDITION, PNP_INFO_HEADER_SIZE,
};

#[cfg(feature = "alloc")]
pub use pdu::{
    AuthenticatedClientMsg, ClientDeviceAdditionMsg, ClientDeviceRemovalMsg, ClientVersionMsg,
    PnpDeviceDescription, PnpInfoHeader, ServerVersionMsg, VersionMsg,
};

#[cfg(feature = "alloc")]
pub use client::{
    DeviceEntry, NullCallback, PnpInfoCallback, PnpInfoClient, PnpInfoError, PnpInfoState,
};

#[cfg(all(test, feature = "alloc"))]
mod client_tests;

#[cfg(all(test, feature = "alloc"))]
mod pdu_tests;
