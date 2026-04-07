#![forbid(unsafe_code)]

//! Smart Card Redirection -- MS-RDPESC
//!
//! Implements the Smart Card Virtual Channel Extension protocol.
//! Smart card I/O is tunneled through RDPDR's `IRP_MJ_DEVICE_CONTROL`
//! on a device of type `RDPDR_DTYP_SMARTCARD` (0x20).
//!
//! # Architecture
//!
//! ```text
//! Server                          Client (us)
//!   │                                │
//!   │── IRP_MJ_DEVICE_CONTROL ──────▶│
//!   │   (IoControlCode = SCARD_*)    │
//!   │   (InputBuffer = RPCE+NDR)     │
//!   │                                ├── decode RPCE envelope
//!   │                                ├── decode NDR call struct
//!   │                                ├── dispatch to ScardBackend
//!   │                                ├── encode NDR return struct
//!   │                                ├── encode RPCE envelope
//!   │◀── DR_DEVICE_IOCOMPLETION ─────┤
//!   │   (OutputBuffer = RPCE+NDR)    │
//! ```

pub mod backend;
pub mod constants;
pub mod ndr;

pub use backend::{
    ConnectResponse, ReaderState, ReaderStateReturn, SCardIoPci, ScardBackend, ScardResult,
    StatusResponse, TransmitResponse,
};
