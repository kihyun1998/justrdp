//! Presentation lifecycle PDUs (MS-RDPEV §2.2.5.1, §2.2.5.2.1, §2.2.5.2.5,
//! §2.2.5.2.6, §2.2.5.2.8, §2.2.5.2.9).
//!
//! These messages bring a presentation up and tear it down:
//!
//! - [`SetChannelParams`] -- first message on every channel; binds the
//!   channel to a `(PresentationId, StreamId)` pair (StreamId is always
//!   0 for the control channel).
//! - [`OnNewPresentation`] -- server announces a new presentation and
//!   the platform cookie that should drive its decoder rollover policy.
//! - [`SetTopologyReq`] / [`SetTopologyRsp`] -- finalises the streams
//!   added so far and acks readiness.
//! - [`ShutdownPresentationReq`] / [`ShutdownPresentationRsp`] -- tears
//!   the presentation back down.
//!
//! All of these PDUs use the Server Data interface
//! (`InterfaceValue=0`). The two `*Req` / `*Rsp` pairs need
//! request/response correlation via the `MessageId` field; a strict
//! decoder rejects mismatched dispatch tuples.

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{FunctionId, InterfaceValue, Mask};
use crate::pdu::guid::{decode_guid, encode_guid, Guid, GUID_SIZE};
use crate::pdu::header::{
    decode_request_header, decode_response_header, encode_header, SharedMsgHeader,
    REQUEST_HEADER_SIZE, RESPONSE_HEADER_SIZE,
};

// ── SetChannelParams (§2.2.5.1) — 20 bytes payload ──────────────────

/// First message on every TSMF channel. Binds the channel to a
/// `(PresentationId, StreamId)` pair; subsequent messages reference
/// streams indirectly via the channel.
///
/// `stream_id == 0` denotes the control channel (per spec the control
/// channel MUST NOT carry `ON_SAMPLE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetChannelParams {
    pub message_id: u32,
    pub presentation_id: Guid,
    pub stream_id: u32,
}

impl SetChannelParams {
    pub const PAYLOAD_SIZE: usize = GUID_SIZE + 4;
    pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for SetChannelParams {
    fn name(&self) -> &'static str {
        "MS-RDPEV::SetChannelParams"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::SetChannelParams,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())?;
        dst.write_u32_le(self.stream_id, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for SetChannelParams {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::SetChannelParams";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::SetChannelParams)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        let stream_id = src.read_u32_le(CTX)?;
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
            stream_id,
        })
    }
}

// ── OnNewPresentation (§2.2.5.2.1) — 20 bytes payload ───────────────

/// Server announces that a new presentation is being created. The
/// `platform_cookie` advises the client which platform to prefer when
/// multiple decoders are available; unknown cookies must be ignored
/// (per spec §3.3.5.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnNewPresentation {
    pub message_id: u32,
    pub presentation_id: Guid,
    /// `TSMM_PLATFORM_COOKIE_*` -- see [`crate::constants::platform_cookie`].
    pub platform_cookie: u32,
}

impl OnNewPresentation {
    pub const PAYLOAD_SIZE: usize = GUID_SIZE + 4;
    pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for OnNewPresentation {
    fn name(&self) -> &'static str {
        "MS-RDPEV::OnNewPresentation"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::OnNewPresentation,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())?;
        dst.write_u32_le(self.platform_cookie, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for OnNewPresentation {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::OnNewPresentation";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::OnNewPresentation)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        let platform_cookie = src.read_u32_le(CTX)?;
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
            platform_cookie,
        })
    }
}

// ── SetTopologyReq (§2.2.5.2.5) — 16 bytes payload ──────────────────

/// Server signals that the presentation's stream topology is finalised
/// and the client must acknowledge with [`SetTopologyRsp`] before
/// sending any other message on the channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetTopologyReq {
    pub message_id: u32,
    pub presentation_id: Guid,
}

impl SetTopologyReq {
    pub const PAYLOAD_SIZE: usize = GUID_SIZE;
    pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for SetTopologyReq {
    fn name(&self) -> &'static str {
        "MS-RDPEV::SetTopologyReq"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::SetTopologyReq,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())
    }
}

impl<'de> Decode<'de> for SetTopologyReq {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::SetTopologyReq";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::SetTopologyReq)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
        })
    }
}

// ── SetTopologyRsp (§2.2.5.2.6) — 8 bytes payload ───────────────────

/// Client acks topology readiness. `topology_ready == 1` means all
/// streams decoded successfully; `0` means setup failed and the server
/// will close the associated streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetTopologyRsp {
    pub message_id: u32,
    pub topology_ready: u32,
    pub result: u32,
}

impl SetTopologyRsp {
    pub const PAYLOAD_SIZE: usize = 8;
    pub const WIRE_SIZE: usize = RESPONSE_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for SetTopologyRsp {
    fn name(&self) -> &'static str {
        "MS-RDPEV::SetTopologyRsp"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::response(InterfaceValue::ServerData, self.message_id);
        encode_header(dst, &header)?;
        dst.write_u32_le(self.topology_ready, self.name())?;
        dst.write_u32_le(self.result, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for SetTopologyRsp {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::SetTopologyRsp";
        let header = decode_response_header(src)?;
        if header.interface_value != InterfaceValue::ServerData {
            return Err(DecodeError::invalid_value(CTX, "header interface"));
        }
        let topology_ready = src.read_u32_le(CTX)?;
        let result = src.read_u32_le(CTX)?;
        Ok(Self {
            message_id: header.message_id,
            topology_ready,
            result,
        })
    }
}

// ── ShutdownPresentationReq (§2.2.5.2.8) — 16 bytes payload ─────────

/// Server tears down a presentation; client MUST reply with
/// [`ShutdownPresentationRsp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownPresentationReq {
    pub message_id: u32,
    pub presentation_id: Guid,
}

impl ShutdownPresentationReq {
    pub const PAYLOAD_SIZE: usize = GUID_SIZE;
    pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for ShutdownPresentationReq {
    fn name(&self) -> &'static str {
        "MS-RDPEV::ShutdownPresentationReq"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::ShutdownPresentationReq,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())
    }
}

impl<'de> Decode<'de> for ShutdownPresentationReq {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::ShutdownPresentationReq";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::ShutdownPresentationReq)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
        })
    }
}

// ── ShutdownPresentationRsp (§2.2.5.2.9) — 4 bytes payload ──────────

/// Client confirms presentation shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownPresentationRsp {
    pub message_id: u32,
    pub result: u32,
}

impl ShutdownPresentationRsp {
    pub const PAYLOAD_SIZE: usize = 4;
    pub const WIRE_SIZE: usize = RESPONSE_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for ShutdownPresentationRsp {
    fn name(&self) -> &'static str {
        "MS-RDPEV::ShutdownPresentationRsp"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::response(InterfaceValue::ServerData, self.message_id);
        encode_header(dst, &header)?;
        dst.write_u32_le(self.result, self.name())
    }
}

impl<'de> Decode<'de> for ShutdownPresentationRsp {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::ShutdownPresentationRsp";
        let header = decode_response_header(src)?;
        if header.interface_value != InterfaceValue::ServerData {
            return Err(DecodeError::invalid_value(CTX, "header interface"));
        }
        let result = src.read_u32_le(CTX)?;
        Ok(Self {
            message_id: header.message_id,
            result,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{platform_cookie, S_OK};
    use alloc::vec;
    use alloc::vec::Vec;

    fn encode_to_vec<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        assert_eq!(cur.pos(), pdu.size(), "size() mismatch for {}", pdu.name());
        buf
    }

    // GUID from spec §4 §11.1: {28fd2a4a-efc7-44a0-bbca-f31789969fd2}
    const SCP_GUID: Guid = Guid([
        0x4a, 0x2a, 0xfd, 0x28, 0xc7, 0xef, 0xa0, 0x44, 0xbb, 0xca, 0xf3, 0x17, 0x89, 0x96, 0x9f,
        0xd2,
    ]);

    // GUID from spec §4 §11.4: {e086049f-d926-45ae-8c0f-3e056af3f7d4}
    const ONP_GUID: Guid = Guid([
        0x9f, 0x04, 0x86, 0xe0, 0x26, 0xd9, 0xae, 0x45, 0x8c, 0x0f, 0x3e, 0x05, 0x6a, 0xf3, 0xf7,
        0xd4,
    ]);

    // NOTE: checklist §11.1 says SET_CHANNEL_PARAMS is "28 bytes (12 header
    // + 16 GUID + 4 StreamId)" but 12 + 16 + 4 = 32. The annotated byte
    // layout in the same section is correct; only the totals line has a
    // typo. We assert against the byte-correct total of 32 below.

    #[test]
    fn set_channel_params_full_layout() {
        // Authoritative byte-for-byte check; total 32 bytes.
        let pdu = SetChannelParams {
            message_id: 0,
            presentation_id: SCP_GUID,
            stream_id: 0,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 32);
        let expected = {
            let mut v: Vec<u8> = vec![
                0x00, 0x00, 0x00, 0x40, // PROXY
                0x00, 0x00, 0x00, 0x00, // MessageId
                0x01, 0x01, 0x00, 0x00, // FunctionId
            ];
            v.extend_from_slice(SCP_GUID.as_bytes());
            v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // StreamId
            v
        };
        assert_eq!(bytes, expected);

        // Roundtrip
        let mut r = ReadCursor::new(&bytes);
        let decoded = SetChannelParams::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn on_new_presentation_matches_spec_wire_vector() {
        // Spec §4 §11.4, total 32 bytes.
        let pdu = OnNewPresentation {
            message_id: 0,
            presentation_id: ONP_GUID,
            platform_cookie: platform_cookie::DSHOW,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 32);
        let expected = {
            let mut v: Vec<u8> = vec![
                0x00, 0x00, 0x00, 0x40, // PROXY
                0x00, 0x00, 0x00, 0x00, // MessageId
                0x05, 0x01, 0x00, 0x00, // FunctionId = ON_NEW_PRESENTATION (0x105)
            ];
            v.extend_from_slice(ONP_GUID.as_bytes());
            v.extend_from_slice(&0x00000002u32.to_le_bytes()); // DSHOW cookie
            v
        };
        assert_eq!(bytes, expected);

        let mut r = ReadCursor::new(&bytes);
        let decoded = OnNewPresentation::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn set_topology_rsp_matches_spec_wire_vector() {
        // Spec §4 §11.5, total 16 bytes.
        let pdu = SetTopologyRsp {
            message_id: 0,
            topology_ready: 1,
            result: S_OK,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 16);
        assert_eq!(
            bytes,
            [
                0x00, 0x00, 0x00, 0x80, // STUB
                0x00, 0x00, 0x00, 0x00, // MessageId
                0x01, 0x00, 0x00, 0x00, // TopologyReady
                0x00, 0x00, 0x00, 0x00, // Result = S_OK
            ]
        );

        let mut r = ReadCursor::new(&bytes);
        let decoded = SetTopologyRsp::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn set_topology_req_roundtrip() {
        let pdu = SetTopologyReq {
            message_id: 42,
            presentation_id: ONP_GUID,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), SetTopologyReq::WIRE_SIZE);
        assert_eq!(bytes.len(), 28);
        let mut r = ReadCursor::new(&bytes);
        let decoded = SetTopologyReq::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn shutdown_presentation_req_roundtrip() {
        let pdu = ShutdownPresentationReq {
            message_id: 9,
            presentation_id: SCP_GUID,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), ShutdownPresentationReq::WIRE_SIZE);
        let mut r = ReadCursor::new(&bytes);
        let decoded = ShutdownPresentationReq::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn shutdown_presentation_rsp_roundtrip() {
        let pdu = ShutdownPresentationRsp {
            message_id: 9,
            result: S_OK,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), ShutdownPresentationRsp::WIRE_SIZE);
        assert_eq!(bytes.len(), 12);
        let mut r = ReadCursor::new(&bytes);
        let decoded = ShutdownPresentationRsp::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn set_channel_params_rejects_wrong_function_id() {
        // PROXY header but FunctionId = ON_NEW_PRESENTATION instead of
        // SET_CHANNEL_PARAMS. Strict dispatch must reject.
        let mut bytes = vec![
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x05, 0x01, 0x00, 0x00, // FunctionId = ON_NEW_PRESENTATION
        ];
        bytes.extend_from_slice(SCP_GUID.as_bytes());
        bytes.extend_from_slice(&[0u8; 4]);
        let mut r = ReadCursor::new(&bytes);
        assert!(SetChannelParams::decode(&mut r).is_err());
    }

    #[test]
    fn set_topology_rsp_rejects_proxy_mask() {
        // Same payload but PROXY header -- must be rejected by the
        // response decoder.
        let bytes = [
            0x00, 0x00, 0x00, 0x40, // PROXY (wrong)
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x01, 0x00, 0x00, 0x00, // TopologyReady
            0x00, 0x00, 0x00, 0x00, // Result
        ];
        let mut r = ReadCursor::new(&bytes);
        assert!(SetTopologyRsp::decode(&mut r).is_err());
    }

    #[test]
    fn message_id_correlation_round_trips() {
        // The req/rsp pair carry the same MessageId; we verify that
        // it survives the round trip on both sides.
        let req = SetTopologyReq {
            message_id: 0xCAFEBABE,
            presentation_id: ONP_GUID,
        };
        let bytes = encode_to_vec(&req);
        let mut r = ReadCursor::new(&bytes);
        let decoded = SetTopologyReq::decode(&mut r).unwrap();
        assert_eq!(decoded.message_id, 0xCAFEBABE);

        let rsp = SetTopologyRsp {
            message_id: 0xCAFEBABE,
            topology_ready: 0,
            result: S_OK,
        };
        let bytes = encode_to_vec(&rsp);
        let mut r = ReadCursor::new(&bytes);
        let decoded = SetTopologyRsp::decode(&mut r).unwrap();
        assert_eq!(decoded.message_id, 0xCAFEBABE);
    }

    #[test]
    fn nil_presentation_id_is_legal() {
        // SET_CHANNEL_PARAMS with the NIL GUID is the bind for a
        // freshly-created channel before the server has assigned a
        // presentation id.
        let pdu = SetChannelParams {
            message_id: 0,
            presentation_id: Guid::NIL,
            stream_id: 0,
        };
        let bytes = encode_to_vec(&pdu);
        let mut r = ReadCursor::new(&bytes);
        let decoded = SetChannelParams::decode(&mut r).unwrap();
        assert_eq!(decoded.presentation_id, Guid::NIL);
    }
}
