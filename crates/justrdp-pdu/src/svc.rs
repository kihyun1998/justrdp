//! Static virtual channel framing (MS-RDPBCGR 2.2.6): every SVC message rides MCS send-data
//! on the channel's MCS ID, prefixed with a `CHANNEL_PDU_HEADER` and split into chunks of at
//! most [`CHANNEL_CHUNK_LENGTH`] bytes (header included). Chunk *reassembly* is stateful and
//! lives in the session machine (the fast-path fragment precedent); this module owns the pure
//! header codec and the outbound chunking.

use crate::cursor::ReadCursor;
use crate::error::DecodeError;

/// The default maximum size of one SVC chunk **including** the 8-byte header
/// (MS-RDPBCGR 2.2.6.1 — clients/servers may negotiate more via the Virtual Channel capset;
/// justrdp advertises exactly this default).
pub const CHANNEL_CHUNK_LENGTH: usize = 1600;

/// This chunk is the first of its message (MS-RDPBCGR 2.2.6.1.1).
pub const CHANNEL_FLAG_FIRST: u32 = 0x0000_0001;
/// This chunk is the last of its message.
pub const CHANNEL_FLAG_LAST: u32 = 0x0000_0002;
/// The chunk data is compressed (`CHANNEL_PACKET_COMPRESSED`). justrdp advertises
/// `VCCAPS_NO_COMPR`, so an inbound compressed chunk is a protocol violation.
pub const CHANNEL_FLAG_PACKET_COMPRESSED: u32 = 0x0020_0000;

/// `CHANNEL_PDU_HEADER` (MS-RDPBCGR 2.2.6.1.1) plus the chunk it frames. `length` is the
/// total length of the *whole message* across all of its chunks, repeated in every chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelChunk<'a> {
    /// Total uncompressed message length (all chunks).
    pub total_length: u32,
    /// `CHANNEL_FLAG_*` bits.
    pub flags: u32,
    /// This chunk's slice of the message.
    pub data: &'a [u8],
}

impl<'a> ChannelChunk<'a> {
    /// Decode one MCS-delivered SVC payload (header + chunk data).
    pub fn decode(payload: &'a [u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(payload, "CHANNEL_PDU_HEADER");
        let total_length = cur.read_u32_le()?;
        let flags = cur.read_u32_le()?;
        let data = cur.read_slice(cur.remaining())?;
        Ok(Self {
            total_length,
            flags,
            data,
        })
    }
}

/// Split `message` into SVC chunk payloads (header + data each), FIRST/LAST flags set per
/// chunk. Each returned payload is ready to be wrapped in an MCS Send Data Request and is at
/// most [`CHANNEL_CHUNK_LENGTH`] bytes long.
pub fn encode_chunks(message: &[u8]) -> Vec<Vec<u8>> {
    const DATA_PER_CHUNK: usize = CHANNEL_CHUNK_LENGTH - 8;
    let total = message.len() as u32;
    let mut chunks: Vec<&[u8]> = message.chunks(DATA_PER_CHUNK).collect();
    if chunks.is_empty() {
        chunks.push(&[]); // a zero-length message is still one (FIRST|LAST) chunk
    }
    let last = chunks.len() - 1;
    chunks
        .iter()
        .enumerate()
        .map(|(i, data)| {
            let mut flags = 0;
            if i == 0 {
                flags |= CHANNEL_FLAG_FIRST;
            }
            if i == last {
                flags |= CHANNEL_FLAG_LAST;
            }
            let mut out = Vec::with_capacity(8 + data.len());
            out.extend_from_slice(&total.to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(data);
            out
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_message_is_one_first_and_last_chunk() {
        let chunks = encode_chunks(&[0xAA, 0xBB]);
        assert_eq!(chunks.len(), 1);
        let chunk = ChannelChunk::decode(&chunks[0]).unwrap();
        assert_eq!(chunk.total_length, 2);
        assert_eq!(chunk.flags, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST);
        assert_eq!(chunk.data, &[0xAA, 0xBB]);
    }

    #[test]
    fn large_message_chunks_at_the_channel_chunk_length() {
        let message = vec![7u8; 4000];
        let chunks = encode_chunks(&message);
        assert_eq!(chunks.len(), 3); // 1592 + 1592 + 816 data bytes
        assert!(chunks.iter().all(|c| c.len() <= CHANNEL_CHUNK_LENGTH));
        let decoded: Vec<ChannelChunk> = chunks
            .iter()
            .map(|c| ChannelChunk::decode(c).unwrap())
            .collect();
        assert_eq!(decoded[0].flags, CHANNEL_FLAG_FIRST);
        assert_eq!(decoded[1].flags, 0);
        assert_eq!(decoded[2].flags, CHANNEL_FLAG_LAST);
        assert!(decoded.iter().all(|c| c.total_length == 4000));
        let reassembled: Vec<u8> = decoded.iter().flat_map(|c| c.data.iter().copied()).collect();
        assert_eq!(reassembled, message);
    }

    #[test]
    fn truncated_header_is_a_typed_error() {
        assert!(matches!(
            ChannelChunk::decode(&[0x01, 0x02, 0x03]).unwrap_err(),
            DecodeError::NotEnoughBytes { .. }
        ));
    }
}
