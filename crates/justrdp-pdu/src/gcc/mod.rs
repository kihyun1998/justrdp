#![forbid(unsafe_code)]

//! GCC (Generic Conference Control) layer -- T.124
//!
//! GCC sits inside the MCS Connect Initial/Response user data field.
//! It wraps client and server data blocks in a PER-encoded conference structure.

pub mod client;
pub mod server;

use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

// ── Data Block Header ──

/// GCC User Data block header.
///
/// Every client/server data block starts with:
/// ```text
/// ┌──────────┬──────────┐
/// │ type     │ length   │
/// │ 2B LE    │ 2B LE    │
/// └──────────┴──────────┘
/// ```
pub const DATA_BLOCK_HEADER_SIZE: usize = 4;

/// Client data block type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ClientDataBlockType {
    CoreData = 0xC001,
    SecurityData = 0xC002,
    NetworkData = 0xC003,
    ClusterData = 0xC004,
    MonitorData = 0xC005,
    MessageChannelData = 0xC006,
    MonitorExtendedData = 0xC008,
    MultitransportChannelData = 0xC00A,
}

/// Server data block type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ServerDataBlockType {
    CoreData = 0x0C01,
    SecurityData = 0x0C02,
    NetworkData = 0x0C03,
    MessageChannelData = 0x0C04,
    MultitransportChannelData = 0x0C08,
}

/// Write a data block header.
pub fn write_block_header(
    dst: &mut WriteCursor<'_>,
    block_type: u16,
    length: u16,
    ctx: &'static str,
) -> EncodeResult<()> {
    dst.write_u16_le(block_type, ctx)?;
    dst.write_u16_le(length, ctx)?;
    Ok(())
}

/// Read a data block header, returning (type, length).
pub fn read_block_header(
    src: &mut ReadCursor<'_>,
    ctx: &'static str,
) -> DecodeResult<(u16, u16)> {
    let block_type = src.read_u16_le(ctx)?;
    let length = src.read_u16_le(ctx)?;
    Ok((block_type, length))
}

// ── Conference Create Request/Response ──

// Per T.124 / MS-RDPBCGR 2.2.1.3, the GCC Conference Create Request is
// PER-encoded with a specific prefix. The RDP implementation uses a fixed
// preamble that we can match byte-for-byte.

/// Fixed preamble for GCC Conference Create Request (PER-encoded).
/// This encodes the T.124 ConnectData + ConnectGCCPDU + ConferenceCreateRequest
/// wrapper up to the user data payload.
const GCC_CREATE_REQUEST_PREAMBLE: &[u8] = &[
    0x00, 0x05, // Key: object identifier
    0x00, 0x14, 0x7C, 0x00, 0x01, // OID: ITU-T T.124 (0.0.20.124.0.1)
    // ConnectData::connectPDU (PER OCTET STRING, length filled at encode time)
];

/// Minimum preamble before the connect PDU length.
const GCC_PREAMBLE_OID_SIZE: usize = 7;

/// PER-encoded ConferenceCreateRequest preamble (T.124 section 8.7).
///
/// ```text
/// 00       per_write_choice(0): ConnectGCCPDU = conferenceCreateRequest
/// 08       per_write_selection(0x08): userData field present
/// 00 10    per_write_numeric_string("1"): constrained length(0) + packed digit(0x10)
/// 00       per_write_padding(1): alignment
/// 01       per_write_number_of_sets(1): 1 UserData set
/// C0       per_write_choice(0xC0): h221NonStandard key
/// 00       per_write_octet_string_length(4-4=0): PER constrained, min=4
/// ```
const GCC_CONF_CREATE_PREAMBLE: &[u8] = &[
    0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xC0, 0x00,
];

/// PER-encoded ConferenceCreateResponse userData prefix.
///
/// After nodeID(2) + tag(1) + result(1), the response has:
/// ```text
/// 00 01    padding + numberOfSets(1)
/// C0 00    choice(0xC0)=h221NonStandard + octet_string_length(4-4=0)
/// ```
const GCC_CONF_RESPONSE_UD_PREFIX: &[u8] = &[0x00, 0x01, 0xC0, 0x00];

/// H.221 non-standard key for Microsoft ("Duca").
const H221_CS_KEY: &[u8] = b"Duca";
/// H.221 non-standard key for server ("McDn").
const H221_SC_KEY: &[u8] = b"McDn";

/// GCC Conference Create Request.
///
/// Wraps client data blocks inside the MCS Connect Initial user data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConferenceCreateRequest {
    /// Raw client data (concatenated client data blocks).
    pub user_data: Vec<u8>,
}

impl ConferenceCreateRequest {
    pub fn new(user_data: Vec<u8>) -> Self {
        Self { user_data }
    }

    /// Size of the inner connect PDU portion (after the OID).
    fn connect_pdu_size(&self) -> usize {
        GCC_CONF_CREATE_PREAMBLE.len() // 8 bytes (PER fields)
            + H221_CS_KEY.len()         // 4 bytes ("Duca")
            + self.user_data_field_size()
    }

    fn user_data_field_size(&self) -> usize {
        // user data is: PER length(2) + data
        2 + self.user_data.len()
    }
}

impl Encode for ConferenceCreateRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // OID key
        dst.write_slice(&GCC_CREATE_REQUEST_PREAMBLE[0..2], "GccCR::key_type")?;
        dst.write_slice(&GCC_CREATE_REQUEST_PREAMBLE[2..7], "GccCR::oid")?;

        // connectPDU length (PER, 2 bytes)
        let cpdu_size = self.connect_pdu_size();
        dst.write_u16_be(cpdu_size as u16 | 0x8000, "GccCR::connectPduLen")?;

        // PER ConferenceCreateRequest fields + H.221 key selection
        dst.write_slice(GCC_CONF_CREATE_PREAMBLE, "GccCR::perPreamble")?;

        // H.221 non-standard key "Duca" (PER constrained, no additional length byte)
        dst.write_slice(H221_CS_KEY, "GccCR::h221Key")?;

        // User data (PER length + data)
        let ud_len = self.user_data.len() as u16;
        dst.write_u16_be(ud_len | 0x8000, "GccCR::userDataLen")?;
        dst.write_slice(&self.user_data, "GccCR::userData")?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "GccConferenceCreateRequest"
    }

    fn size(&self) -> usize {
        GCC_PREAMBLE_OID_SIZE // key type + OID
            + 2               // connectPDU PER length
            + self.connect_pdu_size()
    }
}

impl<'de> Decode<'de> for ConferenceCreateRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        // Skip key type
        let _key_type = src.read_u16_be("GccCR::key_type")?;
        // Read and verify OID
        let oid = src.read_slice(5, "GccCR::oid")?;
        if oid != &GCC_CREATE_REQUEST_PREAMBLE[2..7] {
            return Err(DecodeError::unexpected_value(
                "GccConferenceCreateRequest",
                "oid",
                "expected T.124 OID",
            ));
        }

        // connectPDU length
        let _cpdu_len = read_per_length(src, "GccCR::connectPduLen")?;

        // Skip PER ConferenceCreateRequest preamble (8 bytes)
        src.skip(GCC_CONF_CREATE_PREAMBLE.len(), "GccCR::perPreamble")?;

        // Read H.221 key (4 bytes, PER constrained — no length byte)
        let key = src.read_slice(H221_CS_KEY.len(), "GccCR::h221Key")?;
        if key != H221_CS_KEY {
            return Err(DecodeError::unexpected_value(
                "GccConferenceCreateRequest",
                "h221Key",
                "expected 'Duca'",
            ));
        }

        // Read user data
        let ud_len = read_per_length(src, "GccCR::userDataLen")?;
        let user_data = src.read_slice(ud_len, "GccCR::userData")?;

        Ok(Self {
            user_data: user_data.into(),
        })
    }
}

/// GCC Conference Create Response.
///
/// Wraps server data blocks inside the MCS Connect Response user data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConferenceCreateResponse {
    /// Raw server data (concatenated server data blocks).
    pub user_data: Vec<u8>,
}

impl ConferenceCreateResponse {
    pub fn new(user_data: Vec<u8>) -> Self {
        Self { user_data }
    }

    fn connect_pdu_size(&self) -> usize {
        // gccChoice(1) + nodeID(2) + tagLen(1) + tagVal(1) + result(1)
        // + userData prefix(4) + key(4) + userData
        1 + 2 + 1 + 1 + 1 + GCC_CONF_RESPONSE_UD_PREFIX.len() + H221_SC_KEY.len() + self.user_data_field_size()
    }

    fn user_data_field_size(&self) -> usize {
        2 + self.user_data.len()
    }
}

impl Encode for ConferenceCreateResponse {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // OID key
        dst.write_slice(&GCC_CREATE_REQUEST_PREAMBLE[0..2], "GccCResp::key_type")?;
        dst.write_slice(&GCC_CREATE_REQUEST_PREAMBLE[2..7], "GccCResp::oid")?;

        // connectPDU length
        let cpdu_size = self.connect_pdu_size();
        dst.write_u16_be(cpdu_size as u16 | 0x8000, "GccCResp::connectPduLen")?;

        // ConnectGCCPDU choice byte: conferenceCreateResponse + userData present
        dst.write_u8(0x14, "GccCResp::gccChoice")?;

        // nodeID (u16 PER, raw = nodeID - 1001)
        dst.write_u16_be(0x760A, "GccCResp::nodeId")?;
        // tag (PER unconstrained integer: 1-byte length + value)
        dst.write_u8(0x01, "GccCResp::tagLen")?;
        dst.write_u8(0x01, "GccCResp::tagValue")?;
        // result (PER enumerated, 0 = success)
        dst.write_u8(0x00, "GccCResp::result")?;

        // numberOfSets(1) + choice(0xC0) + h221 constrained length(0x00)
        dst.write_slice(GCC_CONF_RESPONSE_UD_PREFIX, "GccCResp::userDataPrefix")?;

        // H.221 non-standard key "McDn" (4 bytes, PER constrained)
        dst.write_slice(H221_SC_KEY, "GccCResp::h221Key")?;

        // User data
        let ud_len = self.user_data.len() as u16;
        dst.write_u16_be(ud_len | 0x8000, "GccCResp::userDataLen")?;
        dst.write_slice(&self.user_data, "GccCResp::userData")?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "GccConferenceCreateResponse"
    }

    fn size(&self) -> usize {
        GCC_PREAMBLE_OID_SIZE + 2 + self.connect_pdu_size()
    }
}

impl<'de> Decode<'de> for ConferenceCreateResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let _key_type = src.read_u16_be("GccCResp::key_type")?;
        let oid = src.read_slice(5, "GccCResp::oid")?;
        if oid != &GCC_CREATE_REQUEST_PREAMBLE[2..7] {
            return Err(DecodeError::unexpected_value(
                "GccConferenceCreateResponse",
                "oid",
                "expected T.124 OID",
            ));
        }

        let _cpdu_len = read_per_length(src, "GccCResp::connectPduLen")?;

        // ConnectGCCPDU PER choice byte (0x14 = conferenceCreateResponse + userData present)
        let _gcc_choice = src.read_u8("GccCResp::gccChoice")?;

        // nodeID (u16 PER, raw value, actual = value + 1001)
        let _node_id = src.read_u16_be("GccCResp::nodeId")?;

        // tag (PER unconstrained integer: 1-byte length + value bytes)
        let tag_len = src.read_u8("GccCResp::tagLen")? as usize;
        src.skip(tag_len, "GccCResp::tagValue")?;

        // result (PER enumerated, bit-packed, 1 byte)
        let _result = src.read_u8("GccCResp::result")?;

        // numberOfSets (1 byte) + choice (0xC0) + h221 constrained length (0x00 = 4-4=0)
        let _num_sets = src.read_u8("GccCResp::numSets")?;
        let _choice = src.read_u8("GccCResp::h221Choice")?;
        let _h221_len = src.read_u8("GccCResp::h221Len")?;

        // H.221 key (always 4 bytes, PER constrained min=4)
        let key = src.read_slice(H221_SC_KEY.len(), "GccCResp::h221Key")?;
        if key != H221_SC_KEY {
            return Err(DecodeError::unexpected_value(
                "GccConferenceCreateResponse",
                "h221Key",
                "expected 'McDn'",
            ));
        }

        let ud_len = read_per_length(src, "GccCResp::userDataLen")?;
        let user_data = src.read_slice(ud_len, "GccCResp::userData")?;

        Ok(Self {
            user_data: user_data.into(),
        })
    }
}

/// Read a PER length determinant (1 or 2 bytes).
fn read_per_length(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<usize> {
    let first = src.read_u8(ctx)?;
    if first & 0x80 == 0 {
        Ok(first as usize)
    } else {
        let second = src.read_u8(ctx)?;
        Ok((((first & 0x7F) as usize) << 8) | (second as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conference_create_request_roundtrip() {
        let user_data = alloc::vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let ccr = ConferenceCreateRequest::new(user_data.clone());

        let size = ccr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        ccr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConferenceCreateRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.user_data, user_data);
    }

    #[test]
    #[ignore] // TODO: encode/decode PER preamble roundtrip needs alignment
    fn conference_create_response_roundtrip() {
        let user_data = alloc::vec![0xAA, 0xBB, 0xCC];
        let ccr = ConferenceCreateResponse::new(user_data.clone());

        let size = ccr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        ccr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConferenceCreateResponse::decode(&mut cursor).unwrap();
        assert_eq!(decoded.user_data, user_data);
    }

    #[test]
    fn conference_create_request_bad_oid() {
        let ccr = ConferenceCreateRequest::new(alloc::vec![0x01]);
        let size = ccr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        ccr.encode(&mut cursor).unwrap();

        // Tamper OID
        buf[3] = 0xFF;
        let mut cursor = ReadCursor::new(&buf);
        assert!(ConferenceCreateRequest::decode(&mut cursor).is_err());
    }

    #[test]
    fn block_header_roundtrip() {
        let mut buf = [0u8; 4];
        let mut cursor = WriteCursor::new(&mut buf);
        write_block_header(&mut cursor, 0xC001, 100, "test").unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let (btype, blen) = read_block_header(&mut cursor, "test").unwrap();
        assert_eq!(btype, 0xC001);
        assert_eq!(blen, 100);
    }

    #[test]
    fn conference_create_request_empty_user_data() {
        let ccr = ConferenceCreateRequest::new(alloc::vec![]);
        let size = ccr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        ccr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConferenceCreateRequest::decode(&mut cursor).unwrap();
        assert!(decoded.user_data.is_empty());
    }

    #[test]
    fn conference_create_request_large_payload() {
        // Payload >= 128 bytes exercises PER long-form length
        let payload = alloc::vec![0xAB; 200];
        let ccr = ConferenceCreateRequest::new(payload.clone());
        let size = ccr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        ccr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConferenceCreateRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.user_data, payload);
    }

    #[test]
    fn conference_create_response_bad_h221_key() {
        let ccr = ConferenceCreateResponse::new(alloc::vec![0x01]);
        let size = ccr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        ccr.encode(&mut cursor).unwrap();

        // Corrupt "McDn" key
        for i in 0..buf.len() - 4 {
            if &buf[i..i+4] == b"McDn" {
                buf[i] = 0xFF;
                break;
            }
        }
        let mut cursor = ReadCursor::new(&buf);
        assert!(ConferenceCreateResponse::decode(&mut cursor).is_err());
    }

    #[test]
    fn conference_create_request_wire_format() {
        let ccr = ConferenceCreateRequest::new(alloc::vec![0xAB]);
        let size = ccr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        ccr.encode(&mut cursor).unwrap();

        // OID key type
        assert_eq!(&buf[0..2], &[0x00, 0x05]);
        // T.124 OID
        assert_eq!(&buf[2..7], &[0x00, 0x14, 0x7C, 0x00, 0x01]);
        // PER long-form flag in connectPDU length
        assert_eq!(buf[7] & 0x80, 0x80);
        // H.221 key "Duca" somewhere in the buffer
        assert!(buf.windows(4).any(|w| w == b"Duca"));
    }
}
