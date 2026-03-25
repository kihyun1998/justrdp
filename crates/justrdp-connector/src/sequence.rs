#![forbid(unsafe_code)]

//! Sequence trait for the connection state machine.

use justrdp_core::{PduHint, WriteBuf};

use crate::error::ConnectorResult;
use crate::result::Written;
use crate::state::ClientConnectorState;

/// Trait for driving the RDP connection state machine.
///
/// The caller drives the connection loop:
/// 1. Check `next_pdu_hint()` to determine expected framing
/// 2. If `None`: call `step(&[], output)` immediately (send state)
/// 3. If `Some(hint)`: buffer network bytes until `hint.find_size()` returns a size,
///    then call `step(input, output)` with the complete PDU
/// 4. If output has data, write it to the network
/// 5. Repeat until `state()` returns `Connected`
pub trait Sequence {
    /// Returns the current connection state.
    fn state(&self) -> &ClientConnectorState;

    /// Returns a PDU hint for the expected next server PDU.
    ///
    /// - `None`: no input expected (send state — call `step(&[], output)`)
    /// - `Some(hint)`: use the hint to determine PDU boundaries from incoming bytes
    fn next_pdu_hint(&self) -> Option<&dyn PduHint>;

    /// Advance the state machine by one step.
    ///
    /// For send states: `input` should be `&[]`, output will contain encoded PDU.
    /// For wait states: `input` should be the complete PDU bytes from the server.
    fn step(&mut self, input: &[u8], output: &mut WriteBuf) -> ConnectorResult<Written>;
}
