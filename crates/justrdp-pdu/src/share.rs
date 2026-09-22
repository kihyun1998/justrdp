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

/// `compressedType` flag: the payload is bulk-compressed (`PACKET_COMPRESSED`, 2.2.8.1.1.1.2).
pub const PACKET_COMPRESSED: u8 = 0x20;

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
/// `pduType2`: Set Keyboard Indicators PDU (server → client, the lock state; 2.2.8.2.1).
pub const PDU_TYPE2_SET_KEYBOARD_INDICATORS: u8 = 0x29;
/// `pduType2`: Set Error Info PDU (server → client, disconnect reasons).
pub const PDU_TYPE2_SET_ERROR_INFO: u8 = 0x2F;
/// `pduType2`: Input Event PDU (client → server, the slow-path input fallback).
pub const PDU_TYPE2_INPUT: u8 = 0x1C;
/// `pduType2`: Shutdown Request PDU (client → server) — *"please end this session"*.
/// `[MS-RDPBCGR]` 2.2.2.1: the Share Data header **is** the PDU; there is no body.
pub const PDU_TYPE2_SHUTDOWN_REQUEST: u8 = 0x24;
/// `pduType2`: Shutdown Request Denied PDU (server → client), the refusal that answers
/// [`PDU_TYPE2_SHUTDOWN_REQUEST`]. `[MS-RDPBCGR]` 2.2.2.2, and bodyless for the same reason.
pub const PDU_TYPE2_SHUTDOWN_DENIED: u8 = 0x25;

/// `streamId`: low-priority stream.
pub const STREAM_LOW: u8 = 0x01;
/// `streamId`: medium-priority stream (what the finalization PDUs use).
pub const STREAM_MED: u8 = 0x02;
/// `streamId`: high-priority stream.
pub const STREAM_HI: u8 = 0x04;

/// `totalLength` value that is not a length. `[MS-RDPBCGR]` 2.2.8.1.1.1.1: *"If the
/// totalLength field equals 0x8000, then the Share Control Header and any data that follows MAY
/// be interpreted as a T.128 FlowPDU … and MUST be ignored."*
pub const SHARE_CONTROL_FLOW_PDU: u16 = 0x8000;

/// The `pdu_type` [`ShareControlHeader::decode`] gives a Flow Control PDU (issue #309). Outside
/// the four bits `pduType` is masked to, so no real `pduType` can produce it, and every dispatcher's
/// catch-all already skips it — which is what "MUST be ignored" asks for.
pub const PDU_TYPE_FLOW_CONTROL: u16 = SHARE_CONTROL_FLOW_PDU;

/// A decoded `TS_SHARECONTROLHEADER` plus the `shareID` that every user of it carries next
/// (see the module note). `total_length` covers the whole Share Control PDU including the
/// 6-byte header itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareControlHeader {
    /// `totalLength` — the whole PDU's length in bytes, or [`SHARE_CONTROL_FLOW_PDU`].
    ///
    /// **Nothing reads it, and that is recorded rather than accidental** (#309, taking way #2
    /// of `docs/map/invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md`).
    /// Both loops frame by TPKT and decode one Share PDU per MCS indication, so this length
    /// bounds nothing they do. Measured on the real VM across ten IO-channel indications, it
    /// equalled the indication's user data every time. FreeRDP frames from it because it loops
    /// over *several* PDUs per indication; justrdp does not, and that gap is #309's to hold.
    pub total_length: u16,
    /// The PDU type nibble (one of the `PDU_TYPE_*` constants), version bits stripped.
    pub pdu_type: u16,
    /// `PDUSource` — the sender's MCS channel ID (the server's user channel for inbound PDUs).
    pub pdu_source: u16,
    /// `shareID` — the share identifier assigned by the server at Demand Active, or **0 when
    /// the PDU ends before one**.
    ///
    /// It is not part of the six-byte header 2.2.8.1.1.1.1 defines, and a header-only Deactivate
    /// All omits it. Every reader is a Demand Active handler, whose body continues well past it,
    /// so a PDU too short to carry one fails there before a zero can be used.
    pub share_id: u32,
}

impl ShareControlHeader {
    /// Bytes this header occupies when **we** encode it (6-byte control header + 4-byte
    /// `shareID`) — every PDU the client sends carries a share ID. Decode does not require it.
    pub const ENCODED_LEN: usize = 10;

    /// Decode from the start of an MCS user-data payload. Tolerates the version bits being
    /// anything (MS-RDPBCGR says clients should ignore them — some servers send 0).
    ///
    /// Requires the spec's six bytes and no more (#309). This used to read ten unconditionally,
    /// which ended the session on two PDUs a conforming server may send: a T.128 Flow PDU
    /// (eight bytes, marked by [`SHARE_CONTROL_FLOW_PDU`], which 2.2.8.1.1.1.1 says MUST be
    /// ignored) and a header-only Deactivate All (six). Of FreeRDP, IronRDP and justrdp, only
    /// justrdp died on either.
    ///
    /// A Flow PDU comes back as [`PDU_TYPE_FLOW_CONTROL`] with nothing else read, so a caller's
    /// catch-all skips it. A four-byte header — no `pduSource`, which FreeRDP tolerates for
    /// Windows XP — is **still** `NotEnoughBytes`: it violates the header the spec defines, no
    /// server here sends one, and adopting the tolerance is an ADR-0009 call nobody has made.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let total_length = cur.read_u16_le()?;
        if total_length == SHARE_CONTROL_FLOW_PDU {
            return Ok(Self {
                total_length,
                pdu_type: PDU_TYPE_FLOW_CONTROL,
                pdu_source: 0,
                share_id: 0,
            });
        }
        let pdu_type = cur.read_u16_le()? & PDU_TYPE_MASK;
        let pdu_source = cur.read_u16_le()?;
        let share_id = if cur.remaining() >= 4 {
            cur.read_u32_le()?
        } else {
            0
        };
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
    /// `compressedType` — compression type nibble plus flags. [`Self::decode`] refuses
    /// [`PACKET_COMPRESSED`]: justrdp has no bulk decompressor. The other flags and the type
    /// nibble are left unchecked, because without that flag the payload is plain bytes
    /// whatever they say.
    pub compressed_type: u8,
    /// `compressedLength` — describes a compressed payload, which [`Self::decode`] never
    /// admits, so nothing reads it.
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
        if compressed_type & PACKET_COMPRESSED != 0 {
            return Err(DecodeError::InvalidField {
                field: "TS_SHAREDATAHEADER.compressedType",
                reason: "bulk-compressed Share Data PDU, and no bulk decompressor exists",
            });
        }
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

    /// Issue #309. 2.2.8.1.1.1.1 says a `totalLength` of 0x8000 marks a T.128 Flow PDU that
    /// MUST be ignored. Flow PDUs are 8 bytes, and this decoder used to demand 10 — so a
    /// conforming server sending one ended the session with `NotEnoughBytes`. FreeRDP
    /// special-cases the marker; IronRDP survives it by reading only six.
    #[test]
    fn a_flow_control_pdu_decodes_as_something_to_skip() {
        // totalLength, pduTypeFlow, pad, flowIdentifier, flowNumber, pduSource
        let flow = [0x00, 0x80, 0x42, 0x00, 0x01, 0x02, 0xEA, 0x03];
        let mut cur = ReadCursor::new(&flow, "test");
        let hdr = ShareControlHeader::decode(&mut cur)
            .expect("an 8-byte Flow PDU is not malformed, it is a PDU to ignore");
        assert_eq!(hdr.pdu_type, PDU_TYPE_FLOW_CONTROL);
        assert_eq!(hdr.total_length, SHARE_CONTROL_FLOW_PDU);
        // Side condition: a Flow PDU must not come back looking like a real one.
        for real in [
            PDU_TYPE_DEMAND_ACTIVE,
            PDU_TYPE_CONFIRM_ACTIVE,
            PDU_TYPE_DEACTIVATE_ALL,
            PDU_TYPE_DATA,
        ] {
            assert_ne!(hdr.pdu_type, real);
        }
    }

    /// Issue #309. The header 2.2.8.1.1.1.1 defines is six bytes; `shareId` is not in it.
    /// IronRDP records xrdp sending a Deactivate All that stops right there, and this decoder
    /// used to die on one.
    #[test]
    fn a_header_only_deactivate_all_decodes_without_a_share_id() {
        let mut frame = 6u16.to_le_bytes().to_vec();
        frame.extend_from_slice(&(PDU_TYPE_DEACTIVATE_ALL | 0x0010).to_le_bytes());
        frame.extend_from_slice(&1002u16.to_le_bytes());
        let mut cur = ReadCursor::new(&frame, "test");
        let hdr = ShareControlHeader::decode(&mut cur)
            .expect("a six-byte header is the spec's whole header");
        assert_eq!(hdr.pdu_type, PDU_TYPE_DEACTIVATE_ALL);
        assert_eq!(hdr.pdu_source, 1002);
        assert_eq!(hdr.share_id, 0, "absent, and reported as such");
        assert_eq!(cur.remaining(), 0, "and nothing was read past it");
    }

    /// The deliberate non-adoption from #309: a four-byte header omits `pduSource`, which the
    /// spec's header requires. FreeRDP tolerates it for Windows XP; there is no such server here
    /// and no evidence either way, so it stays a typed error — pinned so the choice is visible.
    #[test]
    fn a_header_without_pdu_source_is_still_a_typed_error() {
        let mut frame = 4u16.to_le_bytes().to_vec();
        frame.extend_from_slice(&(PDU_TYPE_DEACTIVATE_ALL | 0x0010).to_le_bytes());
        let mut cur = ReadCursor::new(&frame, "test");
        assert!(matches!(
            ShareControlHeader::decode(&mut cur),
            Err(DecodeError::NotEnoughBytes { .. })
        ));
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
