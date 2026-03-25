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

/// Conference name "1" in PER numeric string + padding.
const GCC_CONF_NAME: &[u8] = &[
    0x00, 0x01, // conference name length = 1
    0x10,       // packed numeric string "1" (0x01 << 4)
];

/// Bytes after conf name: userData present bit + OCTET STRING tag for H221 key.
const GCC_USER_DATA_PREFIX: &[u8] = &[
    0x00, 0x01, // padding + userData present
    0xC0, 0x00, // PER CHOICE: userData (H.221 non-standard)
];

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
        // connectPDU contains: conf create request fields + user data
        GCC_CONF_NAME.len()
            + GCC_USER_DATA_PREFIX.len()
            + 4 // H.221 key (OCTET STRING: length(1) + "Duca"(4) = 5? No: PER octet string)
            + 1 // H.221 key length byte
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

        // Conference name
        dst.write_slice(GCC_CONF_NAME, "GccCR::confName")?;

        // userData present + H.221 CHOICE
        dst.write_slice(GCC_USER_DATA_PREFIX, "GccCR::userDataPrefix")?;

        // H.221 non-standard key "Duca"
        dst.write_u8(H221_CS_KEY.len() as u8, "GccCR::h221KeyLen")?;
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

        // Skip conference name
        src.skip(GCC_CONF_NAME.len(), "GccCR::confName")?;

        // Skip userData prefix
        src.skip(GCC_USER_DATA_PREFIX.len(), "GccCR::userDataPrefix")?;

        // Read H.221 key
        let key_len = src.read_u8("GccCR::h221KeyLen")? as usize;
        let key = src.read_slice(key_len, "GccCR::h221Key")?;
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
        // nodeID(2) + tag(1) + result(1) + userData prefix(4) + H.221 key(1+4) + userData
        2 + 1 + 1 + GCC_USER_DATA_PREFIX.len() + 1 + H221_SC_KEY.len() + self.user_data_field_size()
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

        // Conference Create Response specific fields
        // nodeID (u16 PER integer, value = 0x79F3 = 31219 - 1001 = 30218... typically 0x79F3)
        dst.write_u16_be(0x79F3, "GccCResp::nodeId")?;
        // tag (1 byte)
        dst.write_u8(0x01, "GccCResp::tag")?;
        // result (1 byte ENUMERATED, 0 = success)
        dst.write_u8(0x00, "GccCResp::result")?;

        // userData present + H.221 CHOICE
        dst.write_slice(GCC_USER_DATA_PREFIX, "GccCResp::userDataPrefix")?;

        // H.221 non-standard key "McDn"
        dst.write_u8(H221_SC_KEY.len() as u8, "GccCResp::h221KeyLen")?;
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

        // nodeID, tag, result
        let _node_id = src.read_u16_be("GccCResp::nodeId")?;
        let _tag = src.read_u8("GccCResp::tag")?;
        let _result = src.read_u8("GccCResp::result")?;

        // userData prefix
        src.skip(GCC_USER_DATA_PREFIX.len(), "GccCResp::userDataPrefix")?;

        // H.221 key
        let key_len = src.read_u8("GccCResp::h221KeyLen")? as usize;
        let key = src.read_slice(key_len, "GccCResp::h221Key")?;
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
}
