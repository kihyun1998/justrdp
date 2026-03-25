#![forbid(unsafe_code)]

//! Helper functions for layered PDU encoding.
//!
//! RDP PDUs are nested in multiple layers: TPKT + X.224 DT + MCS + ShareControl + ShareData.
//! These helpers handle the common wrapping patterns.

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Encode, WriteBuf, WriteCursor};

use justrdp_pdu::mcs::SendDataRequest;
use justrdp_pdu::rdp::headers::{
    ShareControlHeader, ShareControlPduType, ShareDataHeader, ShareDataPduType,
    SHARE_CONTROL_HEADER_SIZE, SHARE_DATA_HEADER_SIZE,
};
use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
use justrdp_pdu::x224::{ConnectionRequest, DataTransfer, DATA_TRANSFER_HEADER_SIZE};

use crate::error::ConnectorResult;

/// Encode an X.224 Connection Request wrapped in TPKT.
pub fn encode_connection_request(cr: &ConnectionRequest, output: &mut WriteBuf) -> ConnectorResult<usize> {
    let payload_size = cr.size();
    let total_size = TPKT_HEADER_SIZE + payload_size;

    output.resize(total_size);
    let mut cursor = WriteCursor::new(output.as_mut_slice());

    TpktHeader::for_payload(payload_size).encode(&mut cursor)?;
    cr.encode(&mut cursor)?;

    Ok(total_size)
}

/// Encode a payload wrapped in TPKT + X.224 Data Transfer.
pub fn encode_slow_path(payload: &dyn Encode, output: &mut WriteBuf) -> ConnectorResult<usize> {
    let inner_size = DATA_TRANSFER_HEADER_SIZE + payload.size();
    let total_size = TPKT_HEADER_SIZE + inner_size;

    output.resize(total_size);
    let mut cursor = WriteCursor::new(output.as_mut_slice());

    TpktHeader::for_payload(inner_size).encode(&mut cursor)?;
    DataTransfer.encode(&mut cursor)?;
    payload.encode(&mut cursor)?;

    Ok(total_size)
}

/// Encode a PDU wrapped in TPKT + X.224 DT + MCS SendDataRequest.
pub fn encode_mcs_send_data(
    initiator: u16,
    channel_id: u16,
    inner: &[u8],
    output: &mut WriteBuf,
) -> ConnectorResult<usize> {
    let sdr = SendDataRequest {
        initiator,
        channel_id,
        user_data: inner,
    };

    let mcs_size = DATA_TRANSFER_HEADER_SIZE + sdr.size();
    let total_size = TPKT_HEADER_SIZE + mcs_size;

    output.resize(total_size);
    let mut cursor = WriteCursor::new(output.as_mut_slice());

    TpktHeader::for_payload(mcs_size).encode(&mut cursor)?;
    DataTransfer.encode(&mut cursor)?;
    sdr.encode(&mut cursor)?;

    Ok(total_size)
}

/// Build a ShareControlHeader + inner payload as bytes.
pub fn wrap_share_control(
    pdu_type: ShareControlPduType,
    pdu_source: u16,
    inner: &[u8],
) -> Vec<u8> {
    let total_length = SHARE_CONTROL_HEADER_SIZE + inner.len();
    let hdr = ShareControlHeader {
        total_length: total_length as u16,
        pdu_type,
        pdu_source,
    };

    let mut buf = vec![0u8; total_length];
    let mut cursor = WriteCursor::new(&mut buf);
    // These are infallible for correctly-sized buffers, but we unwrap for safety.
    hdr.encode(&mut cursor).expect("share control header encode");
    cursor.write_slice(inner, "share_control_inner").expect("share control inner");
    buf
}

/// Build a ShareDataHeader + inner payload as bytes.
pub fn wrap_share_data(
    share_id: u32,
    pdu_type2: ShareDataPduType,
    inner: &[u8],
) -> Vec<u8> {
    let total_length = SHARE_DATA_HEADER_SIZE + inner.len();
    let hdr = ShareDataHeader {
        share_id,
        stream_id: 1, // STREAM_LOW
        uncompressed_length: (inner.len() + SHARE_DATA_HEADER_SIZE) as u16,
        pdu_type2,
        compressed_type: 0,
        compressed_length: 0,
    };

    let mut buf = vec![0u8; total_length];
    let mut cursor = WriteCursor::new(&mut buf);
    hdr.encode(&mut cursor).expect("share data header encode");
    cursor.write_slice(inner, "share_data_inner").expect("share data inner");
    buf
}
