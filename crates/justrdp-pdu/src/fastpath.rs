//! Fast-path output framing (MS-RDPBCGR 2.2.9.1.2 `TS_FP_UPDATE_PDU`) — the compact transport
//! modern servers use for virtually all graphics. A fast-path PDU replaces the whole
//! TPKT/X.224/MCS/share stack with a 2–3 byte header; the update payloads inside are the same
//! structures the slow-path Update PDUs carry (bitmap/palette bodies decode with
//! [`crate::update`]).
//!
//! Demultiplexing: the first byte of a TPKT frame is always `0x03`, while a fast-path output
//! header has `action = 0` in its two low bits — `byte & 0x03 == 0` identifies fast-path.

use crate::DecodeError;
use crate::cursor::ReadCursor;

/// `updateCode`: orders.
pub const FP_UPDATE_ORDERS: u8 = 0x0;
/// `updateCode`: bitmap update (a `TS_UPDATE_BITMAP_DATA` body).
pub const FP_UPDATE_BITMAP: u8 = 0x1;
/// `updateCode`: palette update (a `TS_UPDATE_PALETTE_DATA` body).
pub const FP_UPDATE_PALETTE: u8 = 0x2;
/// `updateCode`: synchronize (no payload).
pub const FP_UPDATE_SYNCHRONIZE: u8 = 0x3;
/// `updateCode`: surface commands (the EGFX-era path; later slices).
pub const FP_UPDATE_SURFCMDS: u8 = 0x4;
/// `updateCode`: hide the pointer (the fast-path form of SYSPTR_NULL).
pub const FP_UPDATE_PTR_NULL: u8 = 0x5;
/// `updateCode`: show the default pointer (the fast-path form of SYSPTR_DEFAULT).
pub const FP_UPDATE_PTR_DEFAULT: u8 = 0x6;
/// `updateCode`: server-set pointer position (`TS_FP_POINTERPOSATTRIBUTE`).
pub const FP_UPDATE_PTR_POSITION: u8 = 0x8;
/// `updateCode`: 24-bpp color pointer shape (`TS_FP_COLORPOINTERATTRIBUTE`).
pub const FP_UPDATE_COLOR_POINTER: u8 = 0x9;
/// `updateCode`: re-select a cached pointer (`TS_FP_CACHEDPOINTERATTRIBUTE`).
pub const FP_UPDATE_CACHED_POINTER: u8 = 0xA;
/// `updateCode`: variable-bpp pointer shape (`TS_FP_POINTERATTRIBUTE`).
pub const FP_UPDATE_NEW_POINTER: u8 = 0xB;
/// `updateCode`: large pointer shape (≤384×384; only sent if the client advertises the
/// Large Pointer capability, which this client does not — decoded-and-skipped).
pub const FP_UPDATE_LARGE_POINTER: u8 = 0xC;

/// `fragmentation`: a complete update in one PDU.
pub const FP_FRAGMENT_SINGLE: u8 = 0x0;
/// `fragmentation`: the last fragment.
pub const FP_FRAGMENT_LAST: u8 = 0x1;
/// `fragmentation`: the first fragment.
pub const FP_FRAGMENT_FIRST: u8 = 0x2;
/// `fragmentation`: a middle fragment.
pub const FP_FRAGMENT_NEXT: u8 = 0x3;

/// True if `first_byte` opens a fast-path PDU rather than a TPKT frame.
pub fn is_fastpath(first_byte: u8) -> bool {
    first_byte & 0x03 == 0
}

/// Total length of the fast-path PDU at the start of `buf` (header included), or
/// [`DecodeError::NotEnoughBytes`] while the 2–3 header bytes are still incomplete.
pub fn frame_len(buf: &[u8]) -> Result<usize, DecodeError> {
    let mut cur = ReadCursor::new(buf, "fast-path header");
    let header = cur.read_u8()?;
    if header & 0xC0 != 0 {
        // FASTPATH_OUTPUT_ENCRYPTED / SECURE_CHECKSUM: impossible under TLS security
        // (encryption level none) — the stream has desynced.
        return Err(DecodeError::InvalidField {
            field: "fpOutputHeader.flags",
            reason: "encrypted fast-path output under TLS transport security",
        });
    }
    let length1 = cur.read_u8()?;
    if length1 & 0x80 == 0 {
        Ok(length1 as usize)
    } else {
        let length2 = cur.read_u8()?;
        Ok(((length1 & 0x7F) as usize) << 8 | length2 as usize)
    }
}

/// One update section of a fast-path PDU (a whole update or one fragment of it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastPathUpdate<'a> {
    /// `updateCode` (`FP_UPDATE_*`).
    pub code: u8,
    /// `fragmentation` (`FP_FRAGMENT_*`).
    pub fragmentation: u8,
    /// The update bytes (the body of, e.g., a `TS_UPDATE_BITMAP_DATA` once reassembled).
    pub data: &'a [u8],
}

/// Split one complete fast-path PDU (as sized by [`frame_len`]) into its update sections.
pub fn decode_updates(frame: &[u8]) -> Result<Vec<FastPathUpdate<'_>>, DecodeError> {
    let mut cur = ReadCursor::new(frame, "fast-path pdu");
    cur.read_u8()?; // fpOutputHeader (validated by frame_len)
    let length1 = cur.read_u8()?;
    if length1 & 0x80 != 0 {
        cur.read_u8()?; // length2
    }
    let mut updates = Vec::new();
    while cur.remaining() > 0 {
        let update_header = cur.read_u8()?;
        let code = update_header & 0x0F;
        let fragmentation = update_header >> 4 & 0x03;
        let compression = update_header >> 6 & 0x03;
        if compression & 0x02 != 0 {
            // compressionFlags byte present (FASTPATH_OUTPUT_COMPRESSION_USED).
            let flags = cur.read_u8()?;
            if flags & 0x20 != 0 {
                // PACKET_COMPRESSED: bulk (MPPC) compression — never negotiated by this
                // client (General capset compressionTypes = 0), so a compressed update means
                // the server ignored the negotiation.
                return Err(DecodeError::InvalidField {
                    field: "TS_FP_UPDATE.compressionFlags",
                    reason: "bulk-compressed update was never negotiated",
                });
            }
        }
        let size = cur.read_u16_le()? as usize;
        updates.push(FastPathUpdate {
            code,
            fragmentation,
            data: cur.read_slice(size)?,
        });
    }
    Ok(updates)
}

/// Encode a fast-path output PDU around already-encoded update sections (test/server use).
pub fn encode_pdu(updates: &[(u8, u8, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for &(code, fragmentation, data) in updates {
        body.push(code & 0x0F | (fragmentation & 0x03) << 4);
        body.extend_from_slice(&(data.len() as u16).to_le_bytes());
        body.extend_from_slice(data);
    }
    let total_short = 2 + body.len();
    let mut out = Vec::with_capacity(total_short + 1);
    out.push(0x00); // action fast-path, no flags
    if total_short <= 0x7F {
        out.push(total_short as u8);
    } else {
        let total = total_short + 1; // the length itself takes two bytes
        out.push(0x80 | (total >> 8) as u8);
        out.push(total as u8);
    }
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demux_distinguishes_tpkt_from_fastpath() {
        assert!(!is_fastpath(0x03)); // TPKT version byte
        assert!(is_fastpath(0x00));
        assert!(is_fastpath(0x04)); // action 0, some reserved bits set
    }

    #[test]
    fn short_and_long_lengths_round_trip() {
        let small = encode_pdu(&[(FP_UPDATE_BITMAP, FP_FRAGMENT_SINGLE, &[0xAA; 10])]);
        assert_eq!(frame_len(&small).unwrap(), small.len());
        let updates = decode_updates(&small).unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].code, FP_UPDATE_BITMAP);
        assert_eq!(updates[0].data, &[0xAA; 10]);

        let big = encode_pdu(&[(FP_UPDATE_BITMAP, FP_FRAGMENT_SINGLE, &vec![0xBB; 500])]);
        assert_eq!(frame_len(&big).unwrap(), big.len());
        let updates = decode_updates(&big).unwrap();
        assert_eq!(updates[0].data.len(), 500);
    }

    #[test]
    fn multiple_updates_in_one_pdu() {
        let pdu = encode_pdu(&[
            (FP_UPDATE_SYNCHRONIZE, FP_FRAGMENT_SINGLE, &[]),
            (FP_UPDATE_PALETTE, FP_FRAGMENT_SINGLE, &[1, 2, 3]),
        ]);
        let updates = decode_updates(&pdu).unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[1].data, &[1, 2, 3]);
    }

    #[test]
    fn encrypted_output_is_rejected() {
        assert!(matches!(
            frame_len(&[0x80, 0x05]),
            Err(DecodeError::InvalidField { .. })
        ));
    }

    #[test]
    fn compressed_updates_are_rejected() {
        // updateHeader with compression bit + compressionFlags PACKET_COMPRESSED.
        let pdu = [0x00, 0x08, 0x81, 0x20, 0x01, 0x00, 0xFF];
        assert!(matches!(
            decode_updates(&pdu),
            Err(DecodeError::InvalidField { .. })
        ));
    }
}
