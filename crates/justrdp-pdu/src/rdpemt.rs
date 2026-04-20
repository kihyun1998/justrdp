#![forbid(unsafe_code)]

//! MS-RDPEMT (Multitransport Extension) §2.2 — Tunnel Management PDUs.
//!
//! These PDUs travel on the UDP side-channel after a TLS (reliable) or DTLS
//! (lossy) handshake completes on top of MS-RDPEUDP. Every RDPEMT PDU starts
//! with [`TunnelHeader`] (§2.2.1.1), which packs the 4-bit Action and 4-bit
//! Flags into byte 0 and may carry zero or more [`TunnelSubHeader`]s.
//!
//! Three concrete PDUs are defined here:
//! - [`TunnelCreateRequest`] (§2.2.2.1) — client → server, echoes the
//!   `requestId`/`securityCookie` from the main-channel
//!   `InitiateMultitransportRequest` (MS-RDPBCGR §2.2.15.1).
//! - [`TunnelCreateResponse`] (§2.2.2.2) — server → client, carries an
//!   HRESULT.
//! - [`TunnelData`] (§2.2.2.3) — bidirectional, encapsulates higher-layer
//!   data (typically DVC traffic).

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

// ── Action codes — MS-RDPEMT §2.2.1.1 ──

/// Tunnel Create Request PDU. MS-RDPEMT §2.2.1.1
pub const RDPTUNNEL_ACTION_CREATEREQUEST: u8 = 0x0;
/// Tunnel Create Response PDU. MS-RDPEMT §2.2.1.1
pub const RDPTUNNEL_ACTION_CREATERESPONSE: u8 = 0x1;
/// Tunnel Data PDU. MS-RDPEMT §2.2.1.1
pub const RDPTUNNEL_ACTION_DATA: u8 = 0x2;

// ── SubHeader types — MS-RDPEMT §2.2.1.1.1 ──

/// Auto-detect request subheader (encapsulates MS-RDPBCGR §2.2.14 structures).
pub const TYPE_ID_AUTODETECT_REQUEST: u8 = 0x00;
/// Auto-detect response subheader.
pub const TYPE_ID_AUTODETECT_RESPONSE: u8 = 0x01;

// ── HRESULT — MS-ERREF §2.1, used by §2.2.2.2 ──

/// `S_OK` — successful tunnel creation. Per Appendix A §<2>, the only success
/// HRESULT Windows ever sends; failures drop the connection instead.
pub const HR_S_OK: u32 = 0x0000_0000;

// ── Fixed sizes ──

/// `Action|Flags` (1) + `PayloadLength` (2) + `HeaderLength` (1). MS-RDPEMT §2.2.1.1
pub const TUNNEL_HEADER_BASE_SIZE: usize = 4;
/// Minimum subheader size: `SubHeaderLength` (1) + `SubHeaderType` (1). §2.2.1.1.1
pub const TUNNEL_SUBHEADER_MIN_SIZE: usize = 2;
/// CreateRequest payload: `RequestID` (4) + `Reserved` (4) + `SecurityCookie` (16). §2.2.2.1
pub const TUNNEL_CREATEREQUEST_PAYLOAD_SIZE: usize = 24;
/// CreateResponse payload: `HrResponse` (4). §2.2.2.2
pub const TUNNEL_CREATERESPONSE_PAYLOAD_SIZE: usize = 4;

// ──────────────────────────────────────────────────────────────────────────
// RDP_TUNNEL_SUBHEADER (§2.2.1.1.1)
// ──────────────────────────────────────────────────────────────────────────

/// Optional subheader carried inside [`TunnelHeader`]. Length-prefixed so
/// receivers can skip unknown `sub_header_type` values defensively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSubHeader {
    /// `SubHeaderType` (1 byte). Known values: [`TYPE_ID_AUTODETECT_REQUEST`],
    /// [`TYPE_ID_AUTODETECT_RESPONSE`]. Unknown types are preserved verbatim
    /// on decode.
    pub sub_header_type: u8,
    /// `SubHeaderData`. Length = `SubHeaderLength - 2`.
    pub data: Vec<u8>,
}

impl TunnelSubHeader {
    /// Encoded size in bytes (matches `SubHeaderLength` field value).
    pub fn encoded_size(&self) -> usize {
        TUNNEL_SUBHEADER_MIN_SIZE + self.data.len()
    }
}

impl Encode for TunnelSubHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let size = self.encoded_size();
        if size > u8::MAX as usize {
            return Err(EncodeError::other(
                "TunnelSubHeader",
                "subHeaderLength overflows u8",
            ));
        }
        dst.write_u8(size as u8, "TunnelSubHeader::subHeaderLength")?;
        dst.write_u8(self.sub_header_type, "TunnelSubHeader::subHeaderType")?;
        dst.write_slice(&self.data, "TunnelSubHeader::subHeaderData")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "TunnelSubHeader" }
    fn size(&self) -> usize { self.encoded_size() }
}

impl<'de> Decode<'de> for TunnelSubHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let sub_header_length = src.read_u8("TunnelSubHeader::subHeaderLength")? as usize;
        if sub_header_length < TUNNEL_SUBHEADER_MIN_SIZE {
            return Err(DecodeError::unexpected_value(
                "TunnelSubHeader",
                "subHeaderLength",
                "must be >= 2",
            ));
        }
        let sub_header_type = src.read_u8("TunnelSubHeader::subHeaderType")?;
        let data_len = sub_header_length - TUNNEL_SUBHEADER_MIN_SIZE;
        let data = src.read_slice(data_len, "TunnelSubHeader::subHeaderData")?.to_vec();
        Ok(Self { sub_header_type, data })
    }
}

// ──────────────────────────────────────────────────────────────────────────
// RDP_TUNNEL_HEADER (§2.2.1.1)
// ──────────────────────────────────────────────────────────────────────────

/// Common header for every RDPEMT tunnel PDU (§2.2.1.1).
///
/// Wire layout (little-endian):
/// ```text
/// byte 0: [Flags(7:4) | Action(3:0)]
/// byte 1: PayloadLength low
/// byte 2: PayloadLength high
/// byte 3: HeaderLength
/// byte 4..HeaderLength-1: SubHeaders (variable)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelHeader {
    /// Action (low nibble of byte 0). One of `RDPTUNNEL_ACTION_*`.
    pub action: u8,
    /// Flags (high nibble of byte 0). Spec MUSTs zero (§2.2.1.1).
    pub flags: u8,
    /// `PayloadLength` — bytes following this header, excludes the header itself.
    pub payload_length: u16,
    /// Optional subheaders included in `HeaderLength`.
    pub sub_headers: Vec<TunnelSubHeader>,
}

impl TunnelHeader {
    /// Build a header with no subheaders and `flags = 0`.
    pub fn new(action: u8, payload_length: u16) -> Self {
        Self { action, flags: 0, payload_length, sub_headers: Vec::new() }
    }

    /// Total `HeaderLength` field value: base + every subheader's encoded size.
    pub fn header_length(&self) -> usize {
        TUNNEL_HEADER_BASE_SIZE
            + self
                .sub_headers
                .iter()
                .map(TunnelSubHeader::encoded_size)
                .sum::<usize>()
    }
}

impl Encode for TunnelHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.action > 0x0F {
            return Err(EncodeError::invalid_value(
                "TunnelHeader",
                "action overflows 4 bits",
            ));
        }
        if self.flags > 0x0F {
            return Err(EncodeError::invalid_value(
                "TunnelHeader",
                "flags overflows 4 bits",
            ));
        }
        let header_length = self.header_length();
        if header_length > u8::MAX as usize {
            return Err(EncodeError::other(
                "TunnelHeader",
                "headerLength overflows u8",
            ));
        }
        let byte0 = ((self.flags & 0x0F) << 4) | (self.action & 0x0F);
        dst.write_u8(byte0, "TunnelHeader::action|flags")?;
        dst.write_u16_le(self.payload_length, "TunnelHeader::payloadLength")?;
        dst.write_u8(header_length as u8, "TunnelHeader::headerLength")?;
        for sub in &self.sub_headers {
            sub.encode(dst)?;
        }
        Ok(())
    }
    fn name(&self) -> &'static str { "TunnelHeader" }
    fn size(&self) -> usize { self.header_length() }
}

impl<'de> Decode<'de> for TunnelHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let byte0 = src.read_u8("TunnelHeader::action|flags")?;
        let action = byte0 & 0x0F;
        let flags = (byte0 >> 4) & 0x0F;
        let payload_length = src.read_u16_le("TunnelHeader::payloadLength")?;
        let header_length = src.read_u8("TunnelHeader::headerLength")? as usize;
        if header_length < TUNNEL_HEADER_BASE_SIZE {
            return Err(DecodeError::unexpected_value(
                "TunnelHeader",
                "headerLength",
                "must be >= 4",
            ));
        }
        let mut remaining = header_length - TUNNEL_HEADER_BASE_SIZE;
        let mut sub_headers = Vec::new();
        while remaining > 0 {
            let before = src.remaining();
            let sub = TunnelSubHeader::decode(src)?;
            let consumed = before - src.remaining();
            if consumed > remaining {
                return Err(DecodeError::unexpected_value(
                    "TunnelHeader",
                    "subHeaderLength",
                    "exceeds headerLength budget",
                ));
            }
            remaining -= consumed;
            sub_headers.push(sub);
        }
        Ok(Self { action, flags, payload_length, sub_headers })
    }
}

// ──────────────────────────────────────────────────────────────────────────
// RDP_TUNNEL_CREATEREQUEST (§2.2.2.1)
// ──────────────────────────────────────────────────────────────────────────

/// Tunnel Create Request PDU (§2.2.2.1). Sent by the client over the UDP
/// transport once TLS/DTLS is up. `request_id` and `security_cookie` MUST
/// match the values delivered by the server in the main-channel
/// `InitiateMultitransportRequest` (MS-RDPBCGR §2.2.15.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelCreateRequest {
    pub header: TunnelHeader,
    pub request_id: u32,
    pub reserved: u32,
    pub security_cookie: [u8; 16],
}

impl TunnelCreateRequest {
    /// Build a request with default header (action = CREATEREQUEST, no
    /// subheaders) and `Reserved = 0`.
    pub fn new(request_id: u32, security_cookie: [u8; 16]) -> Self {
        Self {
            header: TunnelHeader::new(
                RDPTUNNEL_ACTION_CREATEREQUEST,
                TUNNEL_CREATEREQUEST_PAYLOAD_SIZE as u16,
            ),
            request_id,
            reserved: 0,
            security_cookie,
        }
    }
}

impl Encode for TunnelCreateRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.action != RDPTUNNEL_ACTION_CREATEREQUEST {
            return Err(EncodeError::invalid_value(
                "TunnelCreateRequest",
                "header.action must be RDPTUNNEL_ACTION_CREATEREQUEST",
            ));
        }
        if self.header.payload_length as usize != TUNNEL_CREATEREQUEST_PAYLOAD_SIZE {
            return Err(EncodeError::invalid_value(
                "TunnelCreateRequest",
                "header.payload_length must be 24",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.request_id, "TunnelCreateRequest::requestID")?;
        dst.write_u32_le(self.reserved, "TunnelCreateRequest::reserved")?;
        dst.write_slice(&self.security_cookie, "TunnelCreateRequest::securityCookie")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "TunnelCreateRequest" }
    fn size(&self) -> usize {
        self.header.header_length() + TUNNEL_CREATEREQUEST_PAYLOAD_SIZE
    }
}

impl<'de> Decode<'de> for TunnelCreateRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = TunnelHeader::decode(src)?;
        if header.action != RDPTUNNEL_ACTION_CREATEREQUEST {
            return Err(DecodeError::unexpected_value(
                "TunnelCreateRequest",
                "action",
                "expected 0x0",
            ));
        }
        if header.payload_length as usize != TUNNEL_CREATEREQUEST_PAYLOAD_SIZE {
            return Err(DecodeError::unexpected_value(
                "TunnelCreateRequest",
                "payloadLength",
                "must be 24",
            ));
        }
        let request_id = src.read_u32_le("TunnelCreateRequest::requestID")?;
        let reserved = src.read_u32_le("TunnelCreateRequest::reserved")?;
        let cookie_bytes = src.read_slice(16, "TunnelCreateRequest::securityCookie")?;
        let mut security_cookie = [0u8; 16];
        security_cookie.copy_from_slice(cookie_bytes);
        Ok(Self { header, request_id, reserved, security_cookie })
    }
}

// ──────────────────────────────────────────────────────────────────────────
// RDP_TUNNEL_CREATERESPONSE (§2.2.2.2)
// ──────────────────────────────────────────────────────────────────────────

/// Tunnel Create Response PDU (§2.2.2.2). `hr_response` is an HRESULT
/// (MS-ERREF §2.1); per Appendix A §<2>, Windows servers only send
/// [`HR_S_OK`] on success and disconnect on failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelCreateResponse {
    pub header: TunnelHeader,
    pub hr_response: u32,
}

impl TunnelCreateResponse {
    pub fn new(hr_response: u32) -> Self {
        Self {
            header: TunnelHeader::new(
                RDPTUNNEL_ACTION_CREATERESPONSE,
                TUNNEL_CREATERESPONSE_PAYLOAD_SIZE as u16,
            ),
            hr_response,
        }
    }

    pub fn is_success(&self) -> bool {
        self.hr_response == HR_S_OK
    }
}

impl Encode for TunnelCreateResponse {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.action != RDPTUNNEL_ACTION_CREATERESPONSE {
            return Err(EncodeError::invalid_value(
                "TunnelCreateResponse",
                "header.action must be RDPTUNNEL_ACTION_CREATERESPONSE",
            ));
        }
        if self.header.payload_length as usize != TUNNEL_CREATERESPONSE_PAYLOAD_SIZE {
            return Err(EncodeError::invalid_value(
                "TunnelCreateResponse",
                "header.payload_length must be 4",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.hr_response, "TunnelCreateResponse::hrResponse")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "TunnelCreateResponse" }
    fn size(&self) -> usize {
        self.header.header_length() + TUNNEL_CREATERESPONSE_PAYLOAD_SIZE
    }
}

impl<'de> Decode<'de> for TunnelCreateResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = TunnelHeader::decode(src)?;
        if header.action != RDPTUNNEL_ACTION_CREATERESPONSE {
            return Err(DecodeError::unexpected_value(
                "TunnelCreateResponse",
                "action",
                "expected 0x1",
            ));
        }
        if header.payload_length as usize != TUNNEL_CREATERESPONSE_PAYLOAD_SIZE {
            return Err(DecodeError::unexpected_value(
                "TunnelCreateResponse",
                "payloadLength",
                "must be 4",
            ));
        }
        let hr_response = src.read_u32_le("TunnelCreateResponse::hrResponse")?;
        Ok(Self { header, hr_response })
    }
}

// ──────────────────────────────────────────────────────────────────────────
// RDP_TUNNEL_DATA (§2.2.2.3)
// ──────────────────────────────────────────────────────────────────────────

/// Tunnel Data PDU (§2.2.2.3). Carries opaque higher-layer bytes (typically
/// DRDYNVC frames after a Soft-Sync migration). Operated in message mode:
/// `header.payload_length` MUST equal `higher_layer_data.len()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelData {
    pub header: TunnelHeader,
    pub higher_layer_data: Vec<u8>,
}

impl TunnelData {
    /// Build a Data PDU. Returns `EncodeError::invalid_value` if
    /// `data.len() > u16::MAX`, since the `PayloadLength` field is only
    /// 16 bits. Uses `EncodeError` (instead of a string) so callers can
    /// `?`-propagate alongside other PDU errors.
    pub fn new(higher_layer_data: Vec<u8>) -> EncodeResult<Self> {
        if higher_layer_data.len() > u16::MAX as usize {
            return Err(EncodeError::invalid_value(
                "TunnelData",
                "higher_layer_data exceeds u16::MAX",
            ));
        }
        Ok(Self {
            header: TunnelHeader::new(
                RDPTUNNEL_ACTION_DATA,
                higher_layer_data.len() as u16,
            ),
            higher_layer_data,
        })
    }
}

impl Encode for TunnelData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.action != RDPTUNNEL_ACTION_DATA {
            return Err(EncodeError::invalid_value(
                "TunnelData",
                "header.action must be RDPTUNNEL_ACTION_DATA",
            ));
        }
        if self.header.payload_length as usize != self.higher_layer_data.len() {
            return Err(EncodeError::invalid_value(
                "TunnelData",
                "header.payload_length != higher_layer_data.len()",
            ));
        }
        self.header.encode(dst)?;
        dst.write_slice(&self.higher_layer_data, "TunnelData::higherLayerData")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "TunnelData" }
    fn size(&self) -> usize {
        self.header.header_length() + self.higher_layer_data.len()
    }
}

impl<'de> Decode<'de> for TunnelData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = TunnelHeader::decode(src)?;
        if header.action != RDPTUNNEL_ACTION_DATA {
            return Err(DecodeError::unexpected_value(
                "TunnelData",
                "action",
                "expected 0x2",
            ));
        }
        let data = src
            .read_slice(header.payload_length as usize, "TunnelData::higherLayerData")?
            .to_vec();
        Ok(Self { header, higher_layer_data: data })
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Dispatch wrapper
// ──────────────────────────────────────────────────────────────────────────

/// Convenience enum that dispatches on the `Action` nibble of the next
/// PDU's first byte. Useful for the connector / receiver loops that don't
/// know the PDU type ahead of time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelPdu {
    CreateRequest(TunnelCreateRequest),
    CreateResponse(TunnelCreateResponse),
    Data(TunnelData),
}

impl Encode for TunnelPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        match self {
            Self::CreateRequest(p) => p.encode(dst),
            Self::CreateResponse(p) => p.encode(dst),
            Self::Data(p) => p.encode(dst),
        }
    }
    fn name(&self) -> &'static str { "TunnelPdu" }
    fn size(&self) -> usize {
        match self {
            Self::CreateRequest(p) => p.size(),
            Self::CreateResponse(p) => p.size(),
            Self::Data(p) => p.size(),
        }
    }
}

impl<'de> Decode<'de> for TunnelPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let byte0 = src.peek_u8("TunnelPdu::action|flags")?;
        let action = byte0 & 0x0F;
        match action {
            RDPTUNNEL_ACTION_CREATEREQUEST => TunnelCreateRequest::decode(src).map(Self::CreateRequest),
            RDPTUNNEL_ACTION_CREATERESPONSE => TunnelCreateResponse::decode(src).map(Self::CreateResponse),
            RDPTUNNEL_ACTION_DATA => TunnelData::decode(src).map(Self::Data),
            _ => Err(DecodeError::unexpected_value(
                "TunnelPdu",
                "action",
                "unknown RDPEMT action code",
            )),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn encode_to_vec<E: Encode>(value: &E) -> Vec<u8> {
        let mut buf = vec![0u8; value.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        value.encode(&mut cursor).unwrap();
        assert_eq!(cursor.remaining(), 0, "size() mismatch for {}", value.name());
        buf
    }

    #[test]
    fn subheader_min_roundtrip() {
        // SubHeaderLength=2, SubHeaderType=0x00, no data
        let sh = TunnelSubHeader { sub_header_type: TYPE_ID_AUTODETECT_REQUEST, data: vec![] };
        let bytes = encode_to_vec(&sh);
        assert_eq!(bytes, [0x02, 0x00]);
        let decoded = TunnelSubHeader::decode(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(decoded, sh);
    }

    #[test]
    fn subheader_with_data_roundtrip() {
        let sh = TunnelSubHeader {
            sub_header_type: TYPE_ID_AUTODETECT_RESPONSE,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let bytes = encode_to_vec(&sh);
        assert_eq!(bytes, [0x06, 0x01, 0xDE, 0xAD, 0xBE, 0xEF]);
        let decoded = TunnelSubHeader::decode(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(decoded, sh);
    }

    #[test]
    fn subheader_unknown_type_preserved() {
        // Unknown SubHeaderType (0x42) is decoded as-is per defensive parsing rule.
        let bytes = [0x03, 0x42, 0xFF];
        let decoded = TunnelSubHeader::decode(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(decoded.sub_header_type, 0x42);
        assert_eq!(decoded.data, vec![0xFF]);
    }

    #[test]
    fn subheader_length_below_min_rejected() {
        // SubHeaderLength = 1 < TUNNEL_SUBHEADER_MIN_SIZE.
        let bytes = [0x01, 0x00];
        let err = TunnelSubHeader::decode(&mut ReadCursor::new(&bytes)).unwrap_err();
        assert_eq!(err.context, "TunnelSubHeader");
    }

    #[test]
    fn header_min_roundtrip() {
        // No subheaders, payload_length = 0.
        let h = TunnelHeader::new(RDPTUNNEL_ACTION_DATA, 0);
        let bytes = encode_to_vec(&h);
        assert_eq!(bytes, [0x02, 0x00, 0x00, 0x04]);
        let decoded = TunnelHeader::decode(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(decoded, h);
        assert_eq!(decoded.header_length(), TUNNEL_HEADER_BASE_SIZE);
    }

    #[test]
    fn header_with_subheaders_roundtrip() {
        let h = TunnelHeader {
            action: RDPTUNNEL_ACTION_DATA,
            flags: 0,
            payload_length: 0,
            sub_headers: vec![
                TunnelSubHeader { sub_header_type: 0x00, data: vec![] },
                TunnelSubHeader { sub_header_type: 0x01, data: vec![0xAA, 0xBB] },
            ],
        };
        // base(4) + sub(2) + sub(4) = 10
        assert_eq!(h.header_length(), 10);
        let bytes = encode_to_vec(&h);
        assert_eq!(bytes[0], 0x02); // action=2, flags=0
        assert_eq!(bytes[3], 10);   // header_length
        let decoded = TunnelHeader::decode(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn header_action_flags_nibble_packing() {
        // flags=0xA, action=0x2 → byte0 = 0xA2
        let h = TunnelHeader {
            action: RDPTUNNEL_ACTION_DATA,
            flags: 0xA,
            payload_length: 0x1234,
            sub_headers: vec![],
        };
        let bytes = encode_to_vec(&h);
        assert_eq!(bytes[0], 0xA2);
        assert_eq!(&bytes[1..3], &[0x34, 0x12]); // LE payload_length
        let decoded = TunnelHeader::decode(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(decoded.action, 0x2);
        assert_eq!(decoded.flags, 0xA);
        assert_eq!(decoded.payload_length, 0x1234);
    }

    #[test]
    fn header_length_below_base_rejected() {
        let bytes = [0x00, 0x00, 0x00, 0x03];
        let err = TunnelHeader::decode(&mut ReadCursor::new(&bytes)).unwrap_err();
        assert_eq!(err.context, "TunnelHeader");
    }

    #[test]
    fn header_action_overflow_rejected_on_encode() {
        let h = TunnelHeader { action: 0x10, flags: 0, payload_length: 0, sub_headers: vec![] };
        let mut buf = [0u8; 4];
        let mut cursor = WriteCursor::new(&mut buf);
        assert!(h.encode(&mut cursor).is_err());
    }

    #[test]
    fn create_request_roundtrip() {
        let cookie = [0xAB; 16];
        let req = TunnelCreateRequest::new(0x01020304, cookie);
        assert_eq!(req.size(), TUNNEL_HEADER_BASE_SIZE + TUNNEL_CREATEREQUEST_PAYLOAD_SIZE);
        let bytes = encode_to_vec(&req);
        // Header: action=0x0, flags=0, payload_length=24 LE, header_length=4
        assert_eq!(&bytes[0..4], &[0x00, 0x18, 0x00, 0x04]);
        // RequestID LE
        assert_eq!(&bytes[4..8], &[0x04, 0x03, 0x02, 0x01]);
        // Reserved = 0
        assert_eq!(&bytes[8..12], &[0x00, 0x00, 0x00, 0x00]);
        // Cookie
        assert_eq!(&bytes[12..28], &[0xAB; 16]);
        let decoded = TunnelCreateRequest::decode(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn create_request_wrong_action_rejected() {
        // Action = 0x1 (CREATERESPONSE) but body is CREATEREQUEST length.
        let mut bytes = vec![0x01, 0x18, 0x00, 0x04];
        bytes.extend_from_slice(&[0u8; TUNNEL_CREATEREQUEST_PAYLOAD_SIZE]);
        assert!(TunnelCreateRequest::decode(&mut ReadCursor::new(&bytes)).is_err());
    }

    #[test]
    fn create_response_roundtrip_s_ok() {
        let resp = TunnelCreateResponse::new(HR_S_OK);
        assert!(resp.is_success());
        let bytes = encode_to_vec(&resp);
        assert_eq!(bytes, [0x01, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);
        let decoded = TunnelCreateResponse::decode(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn create_response_failure_hresult() {
        let resp = TunnelCreateResponse::new(0x8007_000E); // E_OUTOFMEMORY
        assert!(!resp.is_success());
        let bytes = encode_to_vec(&resp);
        let decoded = TunnelCreateResponse::decode(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(decoded.hr_response, 0x8007_000E);
    }

    #[test]
    fn data_zero_length_roundtrip() {
        let pdu = TunnelData::new(vec![]).unwrap();
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes, [0x02, 0x00, 0x00, 0x04]);
        let decoded = TunnelData::decode(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn data_payload_roundtrip() {
        let payload = (0..128u8).collect::<Vec<u8>>();
        let pdu = TunnelData::new(payload.clone()).unwrap();
        let bytes = encode_to_vec(&pdu);
        assert_eq!(&bytes[0..4], &[0x02, 0x80, 0x00, 0x04]);
        assert_eq!(&bytes[4..], payload.as_slice());
        let decoded = TunnelData::decode(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(decoded.higher_layer_data, payload);
    }

    #[test]
    fn data_max_u16_payload() {
        let payload = vec![0x55u8; u16::MAX as usize];
        let pdu = TunnelData::new(payload.clone()).unwrap();
        let bytes = encode_to_vec(&pdu);
        let decoded = TunnelData::decode(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(decoded.higher_layer_data.len(), u16::MAX as usize);
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn data_oversized_rejected() {
        let oversized = vec![0u8; u16::MAX as usize + 1];
        assert!(TunnelData::new(oversized).is_err());
    }

    #[test]
    fn pdu_dispatch_create_request() {
        let req = TunnelCreateRequest::new(7, [0x11; 16]);
        let bytes = encode_to_vec(&req);
        let decoded = TunnelPdu::decode(&mut ReadCursor::new(&bytes)).unwrap();
        match decoded {
            TunnelPdu::CreateRequest(p) => assert_eq!(p, req),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn pdu_dispatch_create_response() {
        let resp = TunnelCreateResponse::new(HR_S_OK);
        let bytes = encode_to_vec(&resp);
        let decoded = TunnelPdu::decode(&mut ReadCursor::new(&bytes)).unwrap();
        match decoded {
            TunnelPdu::CreateResponse(p) => assert_eq!(p, resp),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn pdu_dispatch_data() {
        let data = TunnelData::new(vec![1, 2, 3, 4, 5]).unwrap();
        let bytes = encode_to_vec(&data);
        let decoded = TunnelPdu::decode(&mut ReadCursor::new(&bytes)).unwrap();
        match decoded {
            TunnelPdu::Data(p) => assert_eq!(p, data),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn pdu_dispatch_unknown_action_rejected() {
        // Action=0x3 (unknown), header_length=4
        let bytes = [0x03, 0x00, 0x00, 0x04];
        assert!(TunnelPdu::decode(&mut ReadCursor::new(&bytes)).is_err());
    }

    #[test]
    fn create_response_wrong_action_rejected() {
        // Action = 0x0 (CREATEREQUEST) but body sized as CREATERESPONSE.
        let bytes = [0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
        assert!(TunnelCreateResponse::decode(&mut ReadCursor::new(&bytes)).is_err());
    }

    #[test]
    fn data_wrong_action_rejected() {
        // Action = 0x1 (CREATERESPONSE) where Data was expected.
        let bytes = [0x01, 0x00, 0x00, 0x04];
        assert!(TunnelData::decode(&mut ReadCursor::new(&bytes)).is_err());
    }

    #[test]
    fn create_request_with_subheaders_roundtrip() {
        // Verify subheaders work on a real PDU type (defensive parsing path).
        let mut req = TunnelCreateRequest::new(42, [0xCC; 16]);
        req.header.sub_headers.push(TunnelSubHeader {
            sub_header_type: TYPE_ID_AUTODETECT_REQUEST,
            data: vec![0xDE, 0xAD],
        });
        // header_length now 4 + (2 + 2) = 8, payload_length still 24
        let bytes = encode_to_vec(&req);
        assert_eq!(bytes[3], 8);
        let decoded = TunnelCreateRequest::decode(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(decoded, req);
    }
}
