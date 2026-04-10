#![forbid(unsafe_code)]

//! Virtual channel chunking (sending) -- MS-RDPBCGR 3.1.5.2.1
//!
//! Splits outgoing virtual channel messages into chunks of at most
//! `chunk_size` bytes, each wrapped in a CHANNEL_PDU_HEADER.

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Encode, WriteCursor};
use justrdp_pdu::mcs::SendDataRequest;
use justrdp_pdu::rdp::svc::{
    ChannelPduHeader, CHANNEL_CHUNK_LENGTH, CHANNEL_FLAG_FIRST, CHANNEL_FLAG_LAST,
    CHANNEL_FLAG_SHOW_PROTOCOL, CHANNEL_PDU_HEADER_SIZE,
};
use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
use justrdp_pdu::x224::{DataTransfer, DATA_TRANSFER_HEADER_SIZE};

use crate::{SvcError, SvcResult};

fn frame_size_overflow() -> SvcError {
    SvcError::Protocol(alloc::string::String::from("frame size overflow"))
}

/// Chunk a message and produce wire-ready frames.
///
/// Each frame is a complete TPKT + X.224 DT + MCS SendDataRequest + ChannelPduHeader + chunk_data.
///
/// - `initiator`: the client's MCS user channel ID.
/// - `channel_id`: the MCS channel ID for this virtual channel.
/// - `payload`: the complete uncompressed message data.
/// - `chunk_size`: maximum chunk data size (default: [`CHANNEL_CHUNK_LENGTH`]).
/// - `show_protocol`: forces `CHANNEL_FLAG_SHOW_PROTOCOL` on every chunk
///   (required when `CHANNEL_OPTION_SHOW_PROTOCOL` is set for this channel,
///   and always required for multi-chunk messages per MS-RDPBCGR 3.1.5.2.1).
pub fn chunk_and_encode(
    initiator: u16,
    channel_id: u16,
    payload: &[u8],
    chunk_size: usize,
    show_protocol: bool,
) -> SvcResult<Vec<Vec<u8>>> {
    let chunk_size = if chunk_size == 0 {
        CHANNEL_CHUNK_LENGTH
    } else {
        chunk_size
    };

    let total_length = u32::try_from(payload.len()).map_err(|_| {
        crate::SvcError::Protocol(alloc::format!("payload too large: {} bytes", payload.len()))
    })?;

    if payload.is_empty() {
        let mut flags = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
        if show_protocol {
            flags |= CHANNEL_FLAG_SHOW_PROTOCOL;
        }
        let frame = encode_chunk_frame(initiator, channel_id, total_length, flags, &[])?;
        return Ok(vec![frame]);
    }

    let num_chunks = (payload.len() + chunk_size - 1) / chunk_size;
    let mut frames = Vec::with_capacity(num_chunks);

    for (i, chunk_data) in payload.chunks(chunk_size).enumerate() {
        let mut flags = 0u32;
        if i == 0 {
            flags |= CHANNEL_FLAG_FIRST;
        }
        if i == num_chunks - 1 {
            flags |= CHANNEL_FLAG_LAST;
        }
        // MS-RDPBCGR 3.1.5.2.1: multi-chunk MUST set SHOW_PROTOCOL on all chunks.
        // Also set when CHANNEL_OPTION_SHOW_PROTOCOL is set for the channel.
        if num_chunks > 1 || show_protocol {
            flags |= CHANNEL_FLAG_SHOW_PROTOCOL;
        }

        let frame = encode_chunk_frame(
            initiator,
            channel_id,
            total_length,
            flags,
            chunk_data,
        )?;
        frames.push(frame);
    }

    Ok(frames)
}

/// Encode a single chunk into a complete wire frame.
fn encode_chunk_frame(
    initiator: u16,
    channel_id: u16,
    total_length: u32,
    flags: u32,
    chunk_data: &[u8],
) -> SvcResult<Vec<u8>> {
    let channel_hdr = ChannelPduHeader {
        length: total_length,
        flags,
    };

    // MCS user data = ChannelPduHeader + chunk_data
    let mcs_user_data_len = CHANNEL_PDU_HEADER_SIZE
        .checked_add(chunk_data.len())
        .ok_or_else(frame_size_overflow)?;
    let mut mcs_user_data = vec![0u8; mcs_user_data_len];
    {
        let mut cursor = WriteCursor::new(&mut mcs_user_data);
        channel_hdr.encode(&mut cursor)?;
        cursor.write_slice(chunk_data, "chunk_data")?;
    }

    // Wrap in MCS SendDataRequest
    let sdr = SendDataRequest {
        initiator,
        channel_id,
        user_data: &mcs_user_data,
    };

    let mcs_size = DATA_TRANSFER_HEADER_SIZE
        .checked_add(sdr.size())
        .ok_or_else(frame_size_overflow)?;
    let total_size = TPKT_HEADER_SIZE
        .checked_add(mcs_size)
        .ok_or_else(frame_size_overflow)?;

    let mut frame = vec![0u8; total_size];
    let mut cursor = WriteCursor::new(&mut frame);
    TpktHeader::try_for_payload(mcs_size)?.encode(&mut cursor)?;
    DataTransfer.encode(&mut cursor)?;
    sdr.encode(&mut cursor)?;

    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_core::{Decode, ReadCursor};
    use justrdp_pdu::mcs::{DomainMcsPduType, SendDataRequest};
    use justrdp_pdu::tpkt::TpktHeader;
    use justrdp_pdu::x224::DataTransfer;

    #[test]
    fn single_chunk_small_message() {
        let frames = chunk_and_encode(1007, 1004, b"hello", CHANNEL_CHUNK_LENGTH, false).unwrap();
        assert_eq!(frames.len(), 1);

        // Verify the frame is parseable.
        let frame = &frames[0];
        assert_eq!(frame[0], 0x03); // TPKT version
        let mut src = ReadCursor::new(frame);
        let _tpkt = TpktHeader::decode(&mut src).unwrap();
        let _dt = DataTransfer::decode(&mut src).unwrap();
        // MCS choice byte
        let choice = src.peek_remaining()[0] >> 2;
        assert_eq!(choice, DomainMcsPduType::SendDataRequest as u8);

        let sdr = SendDataRequest::decode(&mut src).unwrap();
        assert_eq!(sdr.channel_id, 1004);

        // Parse ChannelPduHeader from user_data.
        let mut ud_src = ReadCursor::new(sdr.user_data);
        let ch_hdr = ChannelPduHeader::decode(&mut ud_src).unwrap();
        assert_eq!(ch_hdr.length, 5); // total_length = "hello".len()
        assert_eq!(ch_hdr.flags, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST);
        assert_eq!(ud_src.remaining(), 5);
        assert_eq!(ud_src.peek_remaining(), b"hello");
    }

    #[test]
    fn multi_chunk_splits_correctly() {
        let payload = vec![0xAA; 5]; // 5 bytes with chunk_size=2 → 3 chunks
        let frames = chunk_and_encode(1007, 1004, &payload, 2, false).unwrap();
        assert_eq!(frames.len(), 3);

        // Check each chunk's flags.
        for (i, frame) in frames.iter().enumerate() {
            let mut src = ReadCursor::new(frame);
            let _tpkt = TpktHeader::decode(&mut src).unwrap();
            let _dt = DataTransfer::decode(&mut src).unwrap();
            let sdr = SendDataRequest::decode(&mut src).unwrap();
            let mut ud_src = ReadCursor::new(sdr.user_data);
            let ch_hdr = ChannelPduHeader::decode(&mut ud_src).unwrap();

            // All chunks carry the total_length = 5.
            assert_eq!(ch_hdr.length, 5);

            // SHOW_PROTOCOL must be set on all chunks for multi-chunk.
            assert!(ch_hdr.flags & CHANNEL_FLAG_SHOW_PROTOCOL != 0);

            if i == 0 {
                assert!(ch_hdr.flags & CHANNEL_FLAG_FIRST != 0);
                assert!(ch_hdr.flags & CHANNEL_FLAG_LAST == 0);
                assert_eq!(ud_src.remaining(), 2);
            } else if i == 1 {
                assert!(ch_hdr.flags & CHANNEL_FLAG_FIRST == 0);
                assert!(ch_hdr.flags & CHANNEL_FLAG_LAST == 0);
                assert_eq!(ud_src.remaining(), 2);
            } else {
                assert!(ch_hdr.flags & CHANNEL_FLAG_FIRST == 0);
                assert!(ch_hdr.flags & CHANNEL_FLAG_LAST != 0);
                assert_eq!(ud_src.remaining(), 1); // 5 - 2 - 2 = 1
            }
        }
    }

    #[test]
    fn empty_message_produces_single_frame() {
        let frames = chunk_and_encode(1007, 1004, &[], CHANNEL_CHUNK_LENGTH, false).unwrap();
        assert_eq!(frames.len(), 1);
        // Verify FIRST|LAST flags.
        let frame = &frames[0];
        let mut src = ReadCursor::new(frame);
        TpktHeader::decode(&mut src).unwrap();
        DataTransfer::decode(&mut src).unwrap();
        let sdr = SendDataRequest::decode(&mut src).unwrap();
        let mut ud_src = ReadCursor::new(sdr.user_data);
        let ch_hdr = ChannelPduHeader::decode(&mut ud_src).unwrap();
        assert_eq!(ch_hdr.length, 0);
        assert_eq!(ch_hdr.flags, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST);
    }

    #[test]
    fn exact_chunk_size_single_chunk() {
        let payload = vec![0xBB; CHANNEL_CHUNK_LENGTH];
        let frames = chunk_and_encode(1007, 1004, &payload, CHANNEL_CHUNK_LENGTH, false).unwrap();
        assert_eq!(frames.len(), 1); // exactly chunk_size → single chunk
    }

    #[test]
    fn chunk_size_plus_one_two_chunks() {
        let payload = vec![0xCC; CHANNEL_CHUNK_LENGTH + 1];
        let frames = chunk_and_encode(1007, 1004, &payload, CHANNEL_CHUNK_LENGTH, false).unwrap();
        assert_eq!(frames.len(), 2);
    }
}
