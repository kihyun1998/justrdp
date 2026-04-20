#![forbid(unsafe_code)]

//! Internal helpers shared by the HTTP Transport (`transport.rs`) and
//! WebSocket Transport (`ws_transport.rs`) adapters.
//!
//! These used to be duplicated verbatim in both files. Keeping them
//! together prevents the two adapters from drifting (for example, one
//! gaining a bounds check that the other misses).

extern crate alloc;
extern crate std;

use alloc::format;
use alloc::vec::Vec;
use std::io;

use justrdp_core::{Decode, ReadCursor};

use crate::client::GatewayError;
use crate::pdu::{DataPdu, PACKET_HEADER_SIZE};

/// Decode a single `HTTP_DATA_PACKET` PDU off the wire and return its
/// inner RDP payload. The caller is expected to have already confirmed
/// that `bytes` covers exactly one complete PDU (see
/// [`crate::client::find_packet_size`]).
///
/// `ctx` is appended to the short-header error path so the calling
/// transport ("http" / "ws") can be identified in error messages.
pub(crate) fn parse_data_pdu(bytes: &[u8], ctx: &'static str) -> Result<Vec<u8>, GatewayError> {
    if bytes.len() < PACKET_HEADER_SIZE {
        return Err(GatewayError::InvalidState(ctx));
    }
    let mut cur = ReadCursor::new(bytes);
    let pdu = DataPdu::decode(&mut cur).map_err(GatewayError::Decode)?;
    Ok(pdu.data)
}

/// Convert a `Debug`-formattable error into an `io::Error` suitable
/// for propagation through a `Read`/`Write` implementation. The
/// `Debug` output is preserved so callers can inspect the original
/// error after upcast.
pub(crate) fn io_other<E: core::fmt::Debug>(e: E) -> io::Error {
    io::Error::other(format!("{e:?}"))
}
