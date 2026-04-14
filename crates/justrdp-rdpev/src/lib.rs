#![no_std]
#![forbid(unsafe_code)]

//! Video Redirection Virtual Channel Extension -- MS-RDPEV (TSMF)
//!
//! Server-to-client redirection of audio/video playback over the static
//! [`TSMF`](CHANNEL_NAME) DVC. The server-side TS Multimedia Framework
//! (TSMF) feeds presentation, stream, and sample messages down the
//! channel; the client decodes them and hands the payloads to a local
//! media sink.
//!
//! Unlike MS-RDPECAM (§9.9, client→server camera capture) or MS-RDPEVOR
//! (§9.8, server→client video streaming for the modern stack), TSMF is
//! the legacy multimedia path used by Windows 7-era servers. It is
//! deprecated in favour of RDPEVOR/RDPECAM for new deployments but
//! remains required for full server-side compatibility.
//!
//! ## Wire-format quick reference
//!
//! Every PDU starts with a [`SharedMsgHeader`](pdu::header::SharedMsgHeader):
//!
//! - 4 bytes `InterfaceId` -- bits [29:0] are the `InterfaceValue`
//!   (which interface the call targets), bits [31:30] are a [`Mask`](constants::Mask)
//!   discriminator (`STREAM_ID_NONE` for interface-manipulation,
//!   `STREAM_ID_PROXY` for client-bound requests, `STREAM_ID_STUB` for
//!   server-bound responses).
//! - 4 bytes `MessageId` -- correlation id; responses echo the request's id.
//! - 4 bytes `FunctionId` -- present on requests and interface-manipulation
//!   messages; **absent** on responses (`STREAM_ID_STUB`), so a response
//!   header is only 8 bytes on the wire.
//!
//! The single TSMF channel multiplexes multiple presentations (each
//! identified by a 16-byte GUID) and multiple streams within each
//! presentation (each a 32-bit `StreamId`).
//!
//! ## Module layout (see `specs/ms-rdpev-checklist.md`)
//!
//! - [`constants`] -- `InterfaceValue`s, `FunctionId`s, `Mask`, capability
//!   types, platform cookies, error codes
//! - [`pdu`] -- wire-format structs grouped by message family
//!
//! Higher-level processors (`RdpevClient`, `TsmfMediaSink` trait, etc.)
//! land in subsequent steps.

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod constants;

#[cfg(feature = "alloc")]
pub mod pdu;

/// DVC channel name for MS-RDPEV TSMF traffic. ANSI, null-terminated on
/// the wire (the trailing NUL is added by the DRDYNVC layer when it
/// emits the Create PDU).
///
/// MS-RDPEV §2.1.
pub const CHANNEL_NAME: &str = "TSMF";

// ── Public re-exports (kept narrow for now; expanded as steps land) ──

pub use constants::{
    capability_type, function_id, interface_value, platform_cookie, FunctionId, InterfaceValue,
    Mask,
};

#[cfg(feature = "alloc")]
pub use pdu::header::{decode_request_header, decode_response_header, SharedMsgHeader};
