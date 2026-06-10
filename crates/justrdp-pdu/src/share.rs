//! Share Control / Share Data PDU headers (MS-RDPBCGR 2.2.8.1.1.1.1 / 2.2.8.1.1.1.2) — the
//! framing every post-licensing slow-path PDU rides in: Demand/Confirm Active, the finalization
//! PDUs, and (later) the session loop's data PDUs.
//!
//! Layout note: `TS_SHARECONTROLHEADER` proper is 6 bytes (totalLength, pduType, pduSource), and
//! every PDU that uses it follows immediately with `shareID` — Demand/Confirm Active,
//! DeactivateAll, and the Share Data header alike. We fold `share_id` into
//! [`ShareControlHeader`] so all of them share one decode path (ironrdp models it the same way).

use crate::DecodeError;
use crate::cursor::ReadCursor;

/// `pduType` low nibble: Demand Active PDU (server → client).
pub const PDU_TYPE_DEMAND_ACTIVE: u16 = 0x1;
/// `pduType` low nibble: Confirm Active PDU (client → server).
pub const PDU_TYPE_CONFIRM_ACTIVE: u16 = 0x3;
/// `pduType` low nibble: Deactivate All PDU (server → client).
pub const PDU_TYPE_DEACTIVATE_ALL: u16 = 0x6;
/// `pduType` low nibble: Data PDU (a Share Data header follows).
pub const PDU_TYPE_DATA: u16 = 0x7;
/// `pduType` low nibble: Server Redirection PDU (broker; future epic).
pub const PDU_TYPE_SERVER_REDIRECT: u16 = 0xA;

/// `TS_PROTOCOL_VERSION` — the high bits of `pduType`; always `0x0010` on the wire.
const PROTOCOL_VERSION: u16 = 0x0010;
/// Mask isolating the PDU type nibble from `pduType`.
const PDU_TYPE_MASK: u16 = 0x000F;

/// `pduType2`: Update PDU (graphics: bitmap, palette, synchronize).
pub const PDU_TYPE2_UPDATE: u8 = 0x02;
/// `pduType2`: Pointer Update PDU.
pub const PDU_TYPE2_POINTER: u8 = 0x1B;
/// `pduType2`: Synchronize PDU.
pub const PDU_TYPE2_SYNCHRONIZE: u8 = 0x1F;
/// `pduType2`: Control PDU.
pub const PDU_TYPE2_CONTROL: u8 = 0x14;
/// `pduType2`: Font List PDU (client → server).
pub const PDU_TYPE2_FONT_LIST: u8 = 0x27;
/// `pduType2`: Font Map PDU (server → client) — the session-active gate.
pub const PDU_TYPE2_FONT_MAP: u8 = 0x28;
/// `pduType2`: Save Session Info PDU (server → client, logon notifications).
pub const PDU_TYPE2_SAVE_SESSION_INFO: u8 = 0x26;
/// `pduType2`: Set Error Info PDU (server → client, disconnect reasons).
pub const PDU_TYPE2_SET_ERROR_INFO: u8 = 0x2F;

/// `streamId`: low-priority stream.
pub const STREAM_LOW: u8 = 0x01;
/// `streamId`: medium-priority stream (what the finalization PDUs use).
pub const STREAM_MED: u8 = 0x02;
/// `streamId`: high-priority stream.
pub const STREAM_HI: u8 = 0x04;

/// A decoded `TS_SHARECONTROLHEADER` plus the `shareID` that every user of it carries next
/// (see the module note). `total_length` covers the whole Share Control PDU including the
/// 6-byte header itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareControlHeader {
    /// `totalLength` — the whole PDU's length in bytes.
    pub total_length: u16,
    /// The PDU type nibble (one of the `PDU_TYPE_*` constants), version bits stripped.
    pub pdu_type: u16,
    /// `PDUSource` — the sender's MCS channel ID (the server's user channel for inbound PDUs).
    pub pdu_source: u16,
    /// `shareID` — the share identifier assigned by the server at Demand Active.
    pub share_id: u32,
}

impl ShareControlHeader {
    /// Bytes this header occupies on the wire (6-byte control header + 4-byte `shareID`).
    pub const ENCODED_LEN: usize = 10;

    /// Decode from the start of an MCS user-data payload. Tolerates the version bits being
    /// anything (MS-RDPBCGR says clients should ignore them — some servers send 0).
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let total_length = cur.read_u16_le()?;
        let pdu_type = cur.read_u16_le()? & PDU_TYPE_MASK;
        let pdu_source = cur.read_u16_le()?;
        let share_id = cur.read_u32_le()?;
        Ok(Self {
            total_length,
            pdu_type,
            pdu_source,
            share_id,
        })
    }
}

/// Encode a complete Share Control PDU: header (with computed `totalLength`) + `shareID` +
/// `body`. `pdu_type` is one of the `PDU_TYPE_*` constants; the version bits are added here.
pub fn encode_share_control(pdu_type: u16, pdu_source: u16, share_id: u32, body: &[u8]) -> Vec<u8> {
    let total = ShareControlHeader::ENCODED_LEN + body.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u16).to_le_bytes());
    out.extend_from_slice(&(PROTOCOL_VERSION | pdu_type).to_le_bytes());
    out.extend_from_slice(&pdu_source.to_le_bytes());
    out.extend_from_slice(&share_id.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// The `TS_SHAREDATAHEADER` tail that follows [`ShareControlHeader`] in a Data PDU
/// (`pduType` = [`PDU_TYPE_DATA`]): pad, stream ID, uncompressed length, `pduType2`,
/// compression byte, compressed length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareDataHeader {
    /// `streamId` (one of `STREAM_*`).
    pub stream_id: u8,
    /// `uncompressedLength` — informational; decoders should not validate against it (server
    /// implementations disagree on whether headers are included).
    pub uncompressed_length: u16,
    /// `pduType2` — which Share Data PDU follows (one of the `PDU_TYPE2_*` constants).
    pub pdu_type2: u8,
    /// `compressedType` — must be 0 here: compression is never advertised by this client.
    pub compressed_type: u8,
    /// `compressedLength` — 0 when uncompressed.
    pub compressed_length: u16,
}

impl ShareDataHeader {
    /// Bytes this tail occupies on the wire.
    pub const ENCODED_LEN: usize = 8;

    /// Decode the Share Data tail (call after [`ShareControlHeader::decode`] returned
    /// [`PDU_TYPE_DATA`]).
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        cur.read_u8()?; // pad1octet
        let stream_id = cur.read_u8()?;
        let uncompressed_length = cur.read_u16_le()?;
        let pdu_type2 = cur.read_u8()?;
        let compressed_type = cur.read_u8()?;
        let compressed_length = cur.read_u16_le()?;
        Ok(Self {
            stream_id,
            uncompressed_length,
            pdu_type2,
            compressed_type,
            compressed_length,
        })
    }
}

/// Encode a complete Share Data PDU (control header + data tail + `body`). The
/// `uncompressedLength` field is set to the body length (mirroring ironrdp, which interops
/// against Windows with that convention).
pub fn encode_share_data(
    pdu_source: u16,
    share_id: u32,
    stream_id: u8,
    pdu_type2: u8,
    body: &[u8],
) -> Vec<u8> {
    let mut tail = Vec::with_capacity(ShareDataHeader::ENCODED_LEN + body.len());
    tail.push(0); // pad1octet
    tail.push(stream_id);
    tail.extend_from_slice(&(body.len() as u16).to_le_bytes());
    tail.push(pdu_type2);
    tail.push(0); // compressedType: no compression
    tail.extend_from_slice(&0u16.to_le_bytes()); // compressedLength
    tail.extend_from_slice(body);
    encode_share_control(PDU_TYPE_DATA, pdu_source, share_id, &tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_control_round_trip_pins_layout() {
        let frame = encode_share_control(PDU_TYPE_CONFIRM_ACTIVE, 1004, 0x0001_03EA, &[0xAB; 5]);
        // totalLength = 10 header bytes + 5 body bytes.
        assert_eq!(&frame[0..2], &15u16.to_le_bytes());
        // pduType = version 0x0010 | type 0x3.
        assert_eq!(&frame[2..4], &0x0013u16.to_le_bytes());
        assert_eq!(&frame[4..6], &1004u16.to_le_bytes());
        assert_eq!(&frame[6..10], &0x0001_03EAu32.to_le_bytes());
        assert_eq!(&frame[10..], &[0xAB; 5]);

        let mut cur = ReadCursor::new(&frame, "test");
        let hdr = ShareControlHeader::decode(&mut cur).unwrap();
        assert_eq!(hdr.total_length, 15);
        assert_eq!(hdr.pdu_type, PDU_TYPE_CONFIRM_ACTIVE);
        assert_eq!(hdr.pdu_source, 1004);
        assert_eq!(hdr.share_id, 0x0001_03EA);
    }

    #[test]
    fn share_data_round_trip_pins_layout() {
        let frame = encode_share_data(1004, 7, STREAM_MED, PDU_TYPE2_FONT_LIST, &[1, 2, 3, 4]);
        let mut cur = ReadCursor::new(&frame, "test");
        let hdr = ShareControlHeader::decode(&mut cur).unwrap();
        assert_eq!(hdr.pdu_type, PDU_TYPE_DATA);
        assert_eq!(hdr.total_length as usize, frame.len());
        let data = ShareDataHeader::decode(&mut cur).unwrap();
        assert_eq!(data.stream_id, STREAM_MED);
        assert_eq!(data.pdu_type2, PDU_TYPE2_FONT_LIST);
        assert_eq!(data.uncompressed_length, 4);
        assert_eq!(data.compressed_type, 0);
        assert_eq!(data.compressed_length, 0);
        assert_eq!(cur.read_slice(4).unwrap(), &[1, 2, 3, 4]);
    }

    #[test]
    fn version_bits_are_ignored_on_decode() {
        // Some servers send pduType with version bits 0 — the type nibble must still decode.
        let mut frame = encode_share_control(PDU_TYPE_DEACTIVATE_ALL, 1002, 1, &[]);
        frame[2..4].copy_from_slice(&PDU_TYPE_DEACTIVATE_ALL.to_le_bytes());
        let mut cur = ReadCursor::new(&frame, "test");
        let hdr = ShareControlHeader::decode(&mut cur).unwrap();
        assert_eq!(hdr.pdu_type, PDU_TYPE_DEACTIVATE_ALL);
    }
}
