//! Capability exchange PDUs (MS-RDPEV §2.2.4).
//!
//! At the start of every TSMF channel session the server sends an
//! [`ExchangeCapabilitiesReq`] listing the capabilities it supports
//! (version, platform, audio support, network latency); the client
//! replies with an [`ExchangeCapabilitiesRsp`] containing its own
//! capability set and an `HRESULT` Result code.
//!
//! Both PDUs carry a list of [`TsmmCapabilities`] entries. Each entry
//! is a 4-byte `CapabilityType` discriminator, a 4-byte
//! `cbCapabilityLength`, and `cbCapabilityLength` opaque payload bytes.
//! The four currently-defined `CapabilityType`s all carry a single u32
//! payload, but the wire format permits arbitrary byte blobs and we
//! preserve them verbatim so an older client does not reject a
//! capability the spec may add later.
//!
//! ## DoS caps (checklist §10)
//!
//! - At most [`MAX_CAPABILITIES`] entries per list.
//! - Each entry's `pCapabilityData` is at most [`MAX_CAPABILITY_DATA_BYTES`].
//!
//! These bound decode-time allocation against a malicious peer that
//! claims `numHostCapabilities = 0xFFFFFFFF`.

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{
    function_id::EXCHANGE_CAPABILITIES_REQ, FunctionId, InterfaceValue, Mask,
};
use crate::pdu::header::{
    decode_request_header, decode_response_header, encode_header, SharedMsgHeader,
    REQUEST_HEADER_SIZE, RESPONSE_HEADER_SIZE,
};

// ── DoS caps (checklist §10) ────────────────────────────────────────

/// Maximum number of `TSMM_CAPABILITIES` entries either side may send.
///
/// The spec defines four capability types (version, platform, audio
/// support, latency); 16 leaves headroom for additions while bounding
/// decode-time allocation against a malicious peer.
pub const MAX_CAPABILITIES: usize = 16;

/// Maximum bytes in a single `TSMM_CAPABILITIES.pCapabilityData`.
///
/// All currently-defined capability payloads are exactly 4 bytes (a
/// single u32). 1 KiB is generous headroom for forward-compat and
/// caps total decode-time allocation at `MAX_CAPABILITIES * 1024 = 16
/// KiB`.
pub const MAX_CAPABILITY_DATA_BYTES: usize = 1024;

// ── TsmmCapabilities (§2.2.4.3) ─────────────────────────────────────

/// One entry in the capability exchange. `data` carries the opaque
/// payload bytes (typically a single u32 for the four standard types).
///
/// We do not parse `capability_type` further at this layer -- callers
/// that care about a specific type can match on the discriminator and
/// then read `data`. Forward-compatibility: unknown discriminators
/// round-trip unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsmmCapabilities {
    /// `CapabilityType` -- see [`crate::constants::capability_type`].
    pub capability_type: u32,
    /// Opaque capability payload. Must be at most
    /// [`MAX_CAPABILITY_DATA_BYTES`] long.
    pub data: Vec<u8>,
}

impl TsmmCapabilities {
    /// Wire size of this entry (8 bytes fixed header + payload bytes).
    pub fn wire_size(&self) -> usize {
        8 + self.data.len()
    }

    /// Convenience constructor for the four standard u32-payload types.
    pub fn u32_payload(capability_type: u32, value: u32) -> Self {
        Self {
            capability_type,
            data: value.to_le_bytes().to_vec(),
        }
    }

    /// If `data.len() == 4`, returns it as a little-endian u32. Otherwise
    /// returns `None` -- callers needing the strict u32 payload of one
    /// of the standard capability types use this to validate.
    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() == 4 {
            Some(u32::from_le_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ]))
        } else {
            None
        }
    }

    fn encode_inner(&self, dst: &mut WriteCursor<'_>, ctx: &'static str) -> EncodeResult<()> {
        if self.data.len() > MAX_CAPABILITY_DATA_BYTES {
            return Err(EncodeError::invalid_value(ctx, "cbCapabilityLength too large"));
        }
        dst.write_u32_le(self.capability_type, ctx)?;
        dst.write_u32_le(self.data.len() as u32, ctx)?;
        dst.write_slice(&self.data, ctx)?;
        Ok(())
    }

    fn decode_inner(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<Self> {
        let capability_type = src.read_u32_le(ctx)?;
        let len = src.read_u32_le(ctx)?;
        if len as usize > MAX_CAPABILITY_DATA_BYTES {
            return Err(DecodeError::invalid_value(ctx, "cbCapabilityLength too large"));
        }
        // Refuse to allocate `len` bytes if the cursor cannot deliver
        // them: read_slice already bounds-checks, but we double-check
        // against the remaining buffer to surface a clean error before
        // the allocator is involved.
        if (len as usize) > src.remaining() {
            return Err(DecodeError::invalid_value(ctx, "cbCapabilityLength underflow"));
        }
        let data = src.read_slice(len as usize, ctx)?.to_vec();
        Ok(Self {
            capability_type,
            data,
        })
    }
}

fn encode_capability_array(
    dst: &mut WriteCursor<'_>,
    items: &[TsmmCapabilities],
    ctx: &'static str,
) -> EncodeResult<()> {
    if items.len() > MAX_CAPABILITIES {
        return Err(EncodeError::invalid_value(ctx, "numCapabilities too large"));
    }
    dst.write_u32_le(items.len() as u32, ctx)?;
    for item in items {
        item.encode_inner(dst, ctx)?;
    }
    Ok(())
}

fn decode_capability_array(
    src: &mut ReadCursor<'_>,
    ctx: &'static str,
) -> DecodeResult<Vec<TsmmCapabilities>> {
    let n = src.read_u32_le(ctx)?;
    if n as usize > MAX_CAPABILITIES {
        return Err(DecodeError::invalid_value(ctx, "numCapabilities too large"));
    }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        out.push(TsmmCapabilities::decode_inner(src, ctx)?);
    }
    Ok(out)
}

// ── ExchangeCapabilitiesReq (§2.2.4.1) ──────────────────────────────

/// Server-to-client capability advertisement. Always uses the Server
/// Data interface (`InterfaceValue=0`) with a `STREAM_ID_PROXY` mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeCapabilitiesReq {
    /// Correlation id; the client echoes this in the matching
    /// [`ExchangeCapabilitiesRsp`].
    pub message_id: u32,
    /// Capabilities advertised by the server (max [`MAX_CAPABILITIES`]).
    pub capabilities: Vec<TsmmCapabilities>,
}

impl ExchangeCapabilitiesReq {
    pub fn new(message_id: u32, capabilities: Vec<TsmmCapabilities>) -> Self {
        Self {
            message_id,
            capabilities,
        }
    }

    fn payload_size(&self) -> usize {
        4 + self.capabilities.iter().map(TsmmCapabilities::wire_size).sum::<usize>()
    }
}

impl Encode for ExchangeCapabilitiesReq {
    fn name(&self) -> &'static str {
        "MS-RDPEV::ExchangeCapabilitiesReq"
    }

    fn size(&self) -> usize {
        REQUEST_HEADER_SIZE + self.payload_size()
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::ExchangeCapabilitiesReq,
        );
        encode_header(dst, &header)?;
        encode_capability_array(dst, &self.capabilities, self.name())
    }
}

impl<'de> Decode<'de> for ExchangeCapabilitiesReq {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::ExchangeCapabilitiesReq";
        let header = decode_request_header(src)?;
        // Validate dispatch: must be Server Data + ExchangeCapabilitiesReq.
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::ExchangeCapabilitiesReq)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let capabilities = decode_capability_array(src, CTX)?;
        Ok(Self {
            message_id: header.message_id,
            capabilities,
        })
    }
}

impl ExchangeCapabilitiesReq {
    /// Raw `FunctionId` value -- exposed for places that build a header
    /// by hand (the constant on `crate::constants::function_id` is the
    /// authoritative source).
    pub const FUNCTION_ID: u32 = EXCHANGE_CAPABILITIES_REQ;
}

// ── ExchangeCapabilitiesRsp (§2.2.4.2) ──────────────────────────────

/// Client-to-server capability advertisement, also carrying the
/// `Result` HRESULT for the exchange. Always uses the Server Data
/// interface (`InterfaceValue=0`) with a `STREAM_ID_STUB` mask, and
/// the `message_id` MUST echo the matching [`ExchangeCapabilitiesReq`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeCapabilitiesRsp {
    pub message_id: u32,
    pub capabilities: Vec<TsmmCapabilities>,
    /// HRESULT -- `S_OK = 0x00000000` on success.
    pub result: u32,
}

impl ExchangeCapabilitiesRsp {
    pub fn new(message_id: u32, capabilities: Vec<TsmmCapabilities>, result: u32) -> Self {
        Self {
            message_id,
            capabilities,
            result,
        }
    }

    fn payload_size(&self) -> usize {
        4 + self.capabilities.iter().map(TsmmCapabilities::wire_size).sum::<usize>() + 4
    }
}

impl Encode for ExchangeCapabilitiesRsp {
    fn name(&self) -> &'static str {
        "MS-RDPEV::ExchangeCapabilitiesRsp"
    }

    fn size(&self) -> usize {
        RESPONSE_HEADER_SIZE + self.payload_size()
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::response(InterfaceValue::ServerData, self.message_id);
        encode_header(dst, &header)?;
        encode_capability_array(dst, &self.capabilities, self.name())?;
        dst.write_u32_le(self.result, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for ExchangeCapabilitiesRsp {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::ExchangeCapabilitiesRsp";
        let header = decode_response_header(src)?;
        if header.interface_value != InterfaceValue::ServerData {
            return Err(DecodeError::invalid_value(CTX, "header interface"));
        }
        let capabilities = decode_capability_array(src, CTX)?;
        let result = src.read_u32_le(CTX)?;
        Ok(Self {
            message_id: header.message_id,
            capabilities,
            result,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        capability_type, interface_value::SERVER_DATA, platform_capability_flags, S_OK,
    };
    use alloc::vec;

    fn encode_to_vec<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        assert_eq!(cur.pos(), pdu.size(), "size() mismatch for {}", pdu.name());
        buf
    }

    #[test]
    fn tsmm_capabilities_u32_payload_helper() {
        let cap = TsmmCapabilities::u32_payload(capability_type::VERSION, 0x02);
        assert_eq!(cap.wire_size(), 12);
        assert_eq!(cap.as_u32(), Some(0x02));
    }

    #[test]
    fn exchange_capabilities_req_matches_spec_wire_vector() {
        // Wire vector from spec §4 / checklist §11.2 (40 bytes total):
        //   00 00 00 40  InterfaceId (SERVER_DATA | PROXY)
        //   00 00 00 00  MessageId
        //   00 01 00 00  FunctionId = EXCHANGE_CAPABILITIES_REQ (0x100)
        //   02 00 00 00  numHostCapabilities = 2
        //   01 00 00 00  CapabilityType = VERSION
        //   04 00 00 00  cbCapabilityLength = 4
        //   02 00 00 00  pCapabilityData = version 2
        //   02 00 00 00  CapabilityType = PLATFORM
        //   04 00 00 00  cbCapabilityLength = 4
        //   01 00 00 00  pCapabilityData = MMREDIR_CAPABILITY_PLATFORM_MF
        let req = ExchangeCapabilitiesReq::new(
            0,
            vec![
                TsmmCapabilities::u32_payload(capability_type::VERSION, 0x02),
                TsmmCapabilities::u32_payload(
                    capability_type::PLATFORM,
                    platform_capability_flags::MF,
                ),
            ],
        );
        let bytes = encode_to_vec(&req);
        assert_eq!(bytes.len(), 40);
        assert_eq!(
            bytes,
            [
                0x00, 0x00, 0x00, 0x40, // InterfaceId
                0x00, 0x00, 0x00, 0x00, // MessageId
                0x00, 0x01, 0x00, 0x00, // FunctionId = 0x100
                0x02, 0x00, 0x00, 0x00, // numHostCapabilities
                0x01, 0x00, 0x00, 0x00, // CapabilityType = VERSION
                0x04, 0x00, 0x00, 0x00, // cbCapabilityLength
                0x02, 0x00, 0x00, 0x00, // version = 2
                0x02, 0x00, 0x00, 0x00, // CapabilityType = PLATFORM
                0x04, 0x00, 0x00, 0x00, // cbCapabilityLength
                0x01, 0x00, 0x00, 0x00, // MF
            ]
        );

        // Roundtrip
        let mut r = ReadCursor::new(&bytes);
        let decoded = ExchangeCapabilitiesReq::decode(&mut r).unwrap();
        assert_eq!(decoded, req);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn exchange_capabilities_rsp_matches_spec_wire_vector() {
        // Wire vector from spec §4 / checklist §11.3 (40 bytes total):
        //   00 00 00 80  InterfaceId (SERVER_DATA | STUB)
        //   00 00 00 00  MessageId (echoed)
        //   02 00 00 00  numClientCapabilities = 2
        //   01 00 00 00  CapabilityType = VERSION
        //   04 00 00 00  cbCapabilityLength
        //   02 00 00 00  version = 2
        //   02 00 00 00  CapabilityType = PLATFORM
        //   04 00 00 00  cbCapabilityLength
        //   03 00 00 00  MF | DSHOW (0x01 | 0x02 = 0x03)
        //   00 00 00 00  Result = S_OK
        let rsp = ExchangeCapabilitiesRsp::new(
            0,
            vec![
                TsmmCapabilities::u32_payload(capability_type::VERSION, 0x02),
                TsmmCapabilities::u32_payload(
                    capability_type::PLATFORM,
                    platform_capability_flags::MF | platform_capability_flags::DSHOW,
                ),
            ],
            S_OK,
        );
        let bytes = encode_to_vec(&rsp);
        assert_eq!(bytes.len(), 40);
        assert_eq!(
            bytes,
            [
                0x00, 0x00, 0x00, 0x80, // InterfaceId (STUB)
                0x00, 0x00, 0x00, 0x00, // MessageId
                0x02, 0x00, 0x00, 0x00, // numClientCapabilities
                0x01, 0x00, 0x00, 0x00, // VERSION
                0x04, 0x00, 0x00, 0x00, // cbCapabilityLength
                0x02, 0x00, 0x00, 0x00, // version = 2
                0x02, 0x00, 0x00, 0x00, // PLATFORM
                0x04, 0x00, 0x00, 0x00, // cbCapabilityLength
                0x03, 0x00, 0x00, 0x00, // MF | DSHOW
                0x00, 0x00, 0x00, 0x00, // Result = S_OK
            ]
        );

        let mut r = ReadCursor::new(&bytes);
        let decoded = ExchangeCapabilitiesRsp::decode(&mut r).unwrap();
        assert_eq!(decoded, rsp);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn empty_capability_list_is_legal() {
        // numCapabilities = 0 is a degenerate but valid encoding
        // (checklist §12 boundary cases).
        let req = ExchangeCapabilitiesReq::new(7, vec![]);
        let bytes = encode_to_vec(&req);
        assert_eq!(bytes.len(), REQUEST_HEADER_SIZE + 4);
        let mut r = ReadCursor::new(&bytes);
        let decoded = ExchangeCapabilitiesReq::decode(&mut r).unwrap();
        assert!(decoded.capabilities.is_empty());
    }

    #[test]
    fn decode_rejects_too_many_capabilities() {
        // Hand-roll a header + numCapabilities = 17 (one over MAX).
        let mut bytes = vec![
            0x00, 0x00, 0x00, 0x40, // PROXY header
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x00, 0x01, 0x00, 0x00, // EXCHANGE_CAPABILITIES_REQ
        ];
        bytes.extend_from_slice(&((MAX_CAPABILITIES as u32 + 1).to_le_bytes()));
        let mut r = ReadCursor::new(&bytes);
        assert!(ExchangeCapabilitiesReq::decode(&mut r).is_err());
    }

    #[test]
    fn encode_rejects_too_large_capability_data() {
        let cap = TsmmCapabilities {
            capability_type: capability_type::VERSION,
            data: vec![0u8; MAX_CAPABILITY_DATA_BYTES + 1],
        };
        let req = ExchangeCapabilitiesReq::new(0, vec![cap]);
        // size() is computed without validation, but encode() must
        // refuse oversize payloads before writing them.
        let mut buf: Vec<u8> = vec![0u8; req.size()];
        let mut cur = WriteCursor::new(&mut buf);
        assert!(req.encode(&mut cur).is_err());
    }

    #[test]
    fn decode_rejects_too_large_capability_data() {
        // Hand-roll a single-capability list whose cbCapabilityLength
        // exceeds the cap. Decoder must refuse before allocating.
        let mut bytes = vec![
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x00, 0x01, 0x00, 0x00, // FunctionId
            0x01, 0x00, 0x00, 0x00, // numCapabilities = 1
            0x01, 0x00, 0x00, 0x00, // CapabilityType
        ];
        bytes.extend_from_slice(&((MAX_CAPABILITY_DATA_BYTES as u32 + 1).to_le_bytes()));
        let mut r = ReadCursor::new(&bytes);
        assert!(ExchangeCapabilitiesReq::decode(&mut r).is_err());
    }

    #[test]
    fn decode_rejects_short_capability_payload() {
        // numCapabilities = 1, cbCapabilityLength = 8, but only 4 payload bytes follow.
        let mut bytes = vec![
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x00, 0x01, 0x00, 0x00, // FunctionId
            0x01, 0x00, 0x00, 0x00, // numCapabilities
            0x01, 0x00, 0x00, 0x00, // CapabilityType
            0x08, 0x00, 0x00, 0x00, // cbCapabilityLength = 8
            0x00, 0x00, 0x00, 0x00, // only 4 payload bytes
        ];
        let _ = &mut bytes;
        let mut r = ReadCursor::new(&bytes);
        assert!(ExchangeCapabilitiesReq::decode(&mut r).is_err());
    }

    #[test]
    fn decode_rejects_wrong_function_id() {
        // PROXY header but FunctionId = SET_CHANNEL_PARAMS instead of
        // EXCHANGE_CAPABILITIES_REQ. Strict dispatch must reject.
        let bytes = [
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x01, 0x01, 0x00, 0x00, // FunctionId = SET_CHANNEL_PARAMS
            0x00, 0x00, 0x00, 0x00, // numCapabilities = 0
        ];
        let mut r = ReadCursor::new(&bytes);
        assert!(ExchangeCapabilitiesReq::decode(&mut r).is_err());
    }

    #[test]
    fn unknown_capability_type_round_trips() {
        // Forward-compat: an unknown CapabilityType must round-trip
        // unchanged so an old client does not reject a future spec.
        let req = ExchangeCapabilitiesReq::new(
            1,
            vec![TsmmCapabilities {
                capability_type: 0xDEAD_BEEF,
                data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }],
        );
        let bytes = encode_to_vec(&req);
        let mut r = ReadCursor::new(&bytes);
        let decoded = ExchangeCapabilitiesReq::decode(&mut r).unwrap();
        assert_eq!(decoded.capabilities[0].capability_type, 0xDEAD_BEEF);
        assert_eq!(decoded.capabilities[0].data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn message_id_is_correlated_via_header() {
        let req = ExchangeCapabilitiesReq::new(0xCAFEBABE, vec![]);
        let bytes = encode_to_vec(&req);
        let mut r = ReadCursor::new(&bytes);
        let decoded = ExchangeCapabilitiesReq::decode(&mut r).unwrap();
        assert_eq!(decoded.message_id, 0xCAFEBABE);

        // Response must echo the same id (the dispatch layer enforces
        // this, but the PDU itself just stores whatever it gets).
        let rsp = ExchangeCapabilitiesRsp::new(0xCAFEBABE, vec![], S_OK);
        let bytes = encode_to_vec(&rsp);
        let mut r = ReadCursor::new(&bytes);
        let decoded = ExchangeCapabilitiesRsp::decode(&mut r).unwrap();
        assert_eq!(decoded.message_id, 0xCAFEBABE);
    }

    /// `interface_value` field unused at runtime today, but the
    /// constant must compile -- guards against accidental rename.
    #[test]
    fn interface_value_constant_is_zero() {
        assert_eq!(SERVER_DATA, 0);
    }
}
