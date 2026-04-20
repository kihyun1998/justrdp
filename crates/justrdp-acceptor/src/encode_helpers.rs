#![forbid(unsafe_code)]

//! Helper functions for layered server PDU encoding (mirror of the client
//! `encode_helpers`).

use justrdp_core::{Encode, WriteBuf, WriteCursor};

use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
use justrdp_pdu::x224::ConnectionConfirm;

use crate::error::AcceptorResult;

/// Encode an X.224 Connection Confirm wrapped in TPKT.
pub fn encode_connection_confirm(cc: &ConnectionConfirm, output: &mut WriteBuf) -> AcceptorResult<usize> {
    let payload_size = cc.size();
    let total_size = TPKT_HEADER_SIZE + payload_size;

    output.resize(total_size);
    let mut cursor = WriteCursor::new(output.as_mut_slice());

    TpktHeader::try_for_payload(payload_size)?.encode(&mut cursor)?;
    cc.encode(&mut cursor)?;

    Ok(total_size)
}
