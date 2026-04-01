#![forbid(unsafe_code)]

//! Static Virtual Channel PDU -- MS-RDPBCGR 2.2.6.1

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeResult, EncodeResult};

// ── CHANNEL_PDU_HEADER flags (MS-RDPBCGR 2.2.6.1.1) ──

/// First chunk of a fragmented message.
pub const CHANNEL_FLAG_FIRST: u32 = 0x0000_0001;
/// Last chunk of a fragmented message.
pub const CHANNEL_FLAG_LAST: u32 = 0x0000_0002;
/// CHANNEL_PDU_HEADER must be delivered to the virtual channel endpoint.
pub const CHANNEL_FLAG_SHOW_PROTOCOL: u32 = 0x0000_0010;
/// All VC traffic must be suspended (server-to-client only).
pub const CHANNEL_FLAG_SUSPEND: u32 = 0x0000_0020;
/// All VC traffic must be resumed (server-to-client only).
pub const CHANNEL_FLAG_RESUME: u32 = 0x0000_0040;
// ── Compression flags (high 16 bits of CHANNEL_PDU_HEADER::flags) ──

/// Virtual channel data is compressed.
pub const CHANNEL_PACKET_COMPRESSED: u32 = 0x0020_0000;
/// Decompressed data placed at front of history buffer.
pub const CHANNEL_PACKET_AT_FRONT: u32 = 0x0040_0000;
/// Decompressor must reinitialize history buffer.
pub const CHANNEL_PACKET_FLUSHED: u32 = 0x0080_0000;
/// 4-bit mask for compression type field.
pub const CHANNEL_COMPR_TYPE_MASK: u32 = 0x000F_0000;

// ── CHANNEL_DEF::options constants (MS-RDPBCGR 2.2.1.3.4.1) ──

/// Channel has been initialized (unused; server MUST ignore).
pub const CHANNEL_OPTION_INITIALIZED: u32 = 0x8000_0000;
/// Encrypt using RDP bulk encryption (unused; server MUST ignore).
pub const CHANNEL_OPTION_ENCRYPT_RDP: u32 = 0x4000_0000;
/// Encrypt server-to-client (unused; server MUST ignore).
pub const CHANNEL_OPTION_ENCRYPT_SC: u32 = 0x2000_0000;
/// Encrypt client-to-server (unused; server MUST ignore).
pub const CHANNEL_OPTION_ENCRYPT_CS: u32 = 0x1000_0000;
/// High MCS priority.
pub const CHANNEL_OPTION_PRI_HIGH: u32 = 0x0800_0000;
/// Medium MCS priority.
pub const CHANNEL_OPTION_PRI_MED: u32 = 0x0400_0000;
/// Low MCS priority.
pub const CHANNEL_OPTION_PRI_LOW: u32 = 0x0200_0000;
/// Compress if RDP data is being compressed.
pub const CHANNEL_OPTION_COMPRESS_RDP: u32 = 0x0080_0000;
/// Always compress.
pub const CHANNEL_OPTION_COMPRESS: u32 = 0x0040_0000;
/// Show protocol flag (server ignores; wire flag controls visibility).
pub const CHANNEL_OPTION_SHOW_PROTOCOL: u32 = 0x0020_0000;
/// Persistent across remote control transactions.
pub const CHANNEL_REMOTE_CONTROL_PERSISTENT: u32 = 0x0010_0000;

// ── Virtual Channel Capability flags (MS-RDPBCGR 2.2.7.1.10) ──

/// No virtual channel compression.
pub const VCCAPS_NO_COMPR: u32 = 0x0000_0000;
/// Client supports VC compression (server-to-client).
pub const VCCAPS_COMPR_SC: u32 = 0x0000_0001;
/// Server supports VC compression (client-to-server, 8K only).
pub const VCCAPS_COMPR_CS_8K: u32 = 0x0000_0002;

/// Default maximum chunk size (MS-RDPBCGR 2.2.7.1.10).
pub const CHANNEL_CHUNK_LENGTH: usize = 1600;

/// CHANNEL_PDU_HEADER size in bytes.
pub const CHANNEL_PDU_HEADER_SIZE: usize = 8;

// ── CHANNEL_PDU_HEADER (MS-RDPBCGR 2.2.6.1.1) ──

/// Virtual Channel PDU header.
///
/// ```text
/// ┌──────────────┬──────────────┐
/// │ length (u32) │ flags (u32)  │
/// │  4B LE       │  4B LE       │
/// └──────────────┴──────────────┘
/// ```
///
/// `length` is the total uncompressed size of the complete message
/// (same value in every chunk of a multi-chunk sequence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelPduHeader {
    /// Total uncompressed length of the complete channel message.
    pub length: u32,
    /// Control and compression flags.
    pub flags: u32,
}

impl Encode for ChannelPduHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.length, "ChannelPduHeader::length")?;
        dst.write_u32_le(self.flags, "ChannelPduHeader::flags")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ChannelPduHeader"
    }

    fn size(&self) -> usize {
        CHANNEL_PDU_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for ChannelPduHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let length = src.read_u32_le("ChannelPduHeader::length")?;
        let flags = src.read_u32_le("ChannelPduHeader::flags")?;
        Ok(Self { length, flags })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_pdu_header_roundtrip() {
        let hdr = ChannelPduHeader {
            length: 2062,
            flags: CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST,
        };
        let mut buf = [0u8; CHANNEL_PDU_HEADER_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        hdr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ChannelPduHeader::decode(&mut cursor).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn channel_pdu_header_wire_format() {
        // Single-chunk: length=8, flags=FIRST|LAST=0x03
        let hdr = ChannelPduHeader {
            length: 8,
            flags: CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST,
        };
        let mut buf = [0u8; CHANNEL_PDU_HEADER_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        hdr.encode(&mut cursor).unwrap();
        assert_eq!(&buf, &[0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn channel_flag_constants() {
        assert_eq!(CHANNEL_FLAG_FIRST, 0x01);
        assert_eq!(CHANNEL_FLAG_LAST, 0x02);
        assert_eq!(CHANNEL_FLAG_SHOW_PROTOCOL, 0x10);
        assert_eq!(CHANNEL_FLAG_SUSPEND, 0x20);
        assert_eq!(CHANNEL_FLAG_RESUME, 0x40);
        assert_eq!(CHANNEL_PACKET_COMPRESSED, 0x0020_0000);
        assert_eq!(CHANNEL_CHUNK_LENGTH, 1600);
    }

    #[test]
    fn compression_type_extraction() {
        let flags = CHANNEL_PACKET_COMPRESSED | (0x02 << 16); // NCRUSH
        let compr_type = ((flags & CHANNEL_COMPR_TYPE_MASK) >> 16) as u8;
        assert_eq!(compr_type, 0x02);
    }

    #[test]
    fn multi_chunk_first_flags() {
        let flags = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_SHOW_PROTOCOL;
        assert_eq!(flags, 0x11);
        assert!(flags & CHANNEL_FLAG_FIRST != 0);
        assert!(flags & CHANNEL_FLAG_LAST == 0);
        assert!(flags & CHANNEL_FLAG_SHOW_PROTOCOL != 0);
    }
}
