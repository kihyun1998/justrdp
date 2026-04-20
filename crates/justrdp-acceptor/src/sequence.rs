#![forbid(unsafe_code)]

//! Sequence trait for the server acceptance state machine.

use justrdp_core::{PduHint, WriteBuf};

use crate::error::AcceptorResult;
use crate::result::Written;
use crate::state::ServerAcceptorState;

/// Trait for driving the RDP server acceptance state machine.
///
/// Mirror of `justrdp_connector::Sequence` from the server side. The caller
/// drives the loop:
/// 1. Check `next_pdu_hint()` to determine expected framing.
/// 2. If `None`: call `step(&[], output)` immediately (send state).
/// 3. If `Some(hint)`: buffer network bytes until `hint.find_size()` returns
///    a size, then call `step(input, output)` with the complete client PDU.
/// 4. If output has data, write it to the network.
/// 5. Repeat until `state()` returns `Accepted` or `NegotiationFailed`.
pub trait Sequence {
    /// Returns the current acceptance state.
    fn state(&self) -> &ServerAcceptorState;

    /// Returns a PDU hint for the expected next client PDU.
    ///
    /// - `None`: no input expected (send state -- call `step(&[], output)`).
    /// - `Some(hint)`: use the hint to determine PDU boundaries from incoming
    ///   bytes.
    fn next_pdu_hint(&self) -> Option<&dyn PduHint>;

    /// Advance the state machine by one step.
    ///
    /// For send states: `input` should be `&[]`, output will contain the
    /// encoded server PDU. For wait states: `input` should be the complete
    /// client PDU bytes.
    ///
    /// **Output flush on error.** When `step()` returns `Err`, `output` may
    /// still contain bytes that the caller MUST flush to the wire before
    /// closing the connection. This applies in particular to the
    /// `NegotiationFailed` transition: the server is required by
    /// MS-RDPBCGR §2.2.1.2.2 to send the `RDP_NEG_FAILURE` PDU before
    /// disconnecting so that the client can display a coherent error.
    /// Always flush `output` first, then inspect the error.
    fn step(&mut self, input: &[u8], output: &mut WriteBuf) -> AcceptorResult<Written>;
}
