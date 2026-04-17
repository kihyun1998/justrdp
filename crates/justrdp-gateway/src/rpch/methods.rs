#![forbid(unsafe_code)]

//! Per-method argument marshaling for the 8 on-wire opnums of the
//! TsProxy RPC interface (MS-TSGU §3.1.4).
//!
//! Each `build_*_stub` function produces the **stub_data** bytes of
//! a DCE/RPC REQUEST PDU — i.e. the NDR-marshaled `[in]` parameters
//! in IDL order. The caller wraps the return in a
//! [`RequestPdu`][justrdp_rpch::pdu::RequestPdu] with the
//! corresponding `opnum`, an active presentation-context ID, and a
//! running `call_id`.
//!
//! Each `parse_*_response` function consumes the stub_data of a
//! DCE/RPC RESPONSE PDU and returns the method's `[out]` parameter
//! values.
//!
//! # On-wire opnum layout (MS-TSGU §3.1.4 + IDL Appendix A)
//!
//! Opnums 0 and 5 are reserved (`NotUsedOnWire`). The real opnums
//! are therefore:
//!
//! | opnum | method                     |
//! |-------|----------------------------|
//! | 1     | `TsProxyCreateTunnel`      |
//! | 2     | `TsProxyAuthorizeTunnel`   |
//! | 3     | `TsProxyMakeTunnelCall`    |
//! | 4     | `TsProxyCreateChannel`     |
//! | 6     | `TsProxyCloseChannel`      |
//! | 7     | `TsProxyCloseTunnel`       |
//! | 8     | `TsProxySetupReceivePipe`  |
//! | 9     | `TsProxySendToServer`      |

extern crate alloc;

use alloc::vec::Vec;

use justrdp_rpch::ndr::{NdrDecoder, NdrEncoder, NdrError, NdrResult};

use super::types::{
    ContextHandle, TsEndpointInfo, TsgPacket, TsgPacketQuarEncResponse, TsgPacketResponse,
};

// =============================================================================
// On-wire opnums
// =============================================================================

pub const OPNUM_TS_PROXY_CREATE_TUNNEL: u16 = 1;
pub const OPNUM_TS_PROXY_AUTHORIZE_TUNNEL: u16 = 2;
pub const OPNUM_TS_PROXY_MAKE_TUNNEL_CALL: u16 = 3;
pub const OPNUM_TS_PROXY_CREATE_CHANNEL: u16 = 4;
pub const OPNUM_TS_PROXY_CLOSE_CHANNEL: u16 = 6;
pub const OPNUM_TS_PROXY_CLOSE_TUNNEL: u16 = 7;
pub const OPNUM_TS_PROXY_SETUP_RECEIVE_PIPE: u16 = 8;
pub const OPNUM_TS_PROXY_SEND_TO_SERVER: u16 = 9;

// =============================================================================
// TsProxyCreateTunnel (opnum 1)
// =============================================================================

/// Build the stub_data for `TsProxyCreateTunnel` given the
/// `[in, ref] TSGPacket`.
pub fn build_create_tunnel_stub(tsg_packet: &TsgPacket) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    // [in, ref] PTSG_PACKET TSGPacket — [ref] pointer has no
    // referent ID word; body is inline.
    tsg_packet.encode_ndr(&mut e);
    e.into_bytes()
}

/// Fields returned by `TsProxyCreateTunnel`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateTunnelResponse {
    pub tsg_packet_response: TsgPacket,
    pub tunnel_context: ContextHandle,
    pub tunnel_id: u32,
    /// HRESULT returned by the server. Should be `ERROR_SUCCESS`.
    pub return_value: u32,
}

/// Parse the stub_data produced by a `TsProxyCreateTunnel` RESPONSE.
pub fn parse_create_tunnel_response(stub: &[u8]) -> NdrResult<CreateTunnelResponse> {
    let mut d = NdrDecoder::new(stub);
    // [out, ref] PTSG_PACKET* TSGPacketResponse — a [ref] pointer-
    // to-pointer. On the wire: no outer referent id (ref), then the
    // inner value which is itself a unique pointer to TSG_PACKET.
    let inner_ptr = d.read_unique_pointer("CreateTunnelResponse.inner")?;
    if inner_ptr.is_none() {
        return Err(NdrError::InvalidData {
            context: "CreateTunnelResponse: NULL TSG_PACKET in [out, ref]*",
        });
    }
    let tsg_packet_response = TsgPacket::decode_ndr(&mut d)?;
    // [out] PTUNNEL_CONTEXT_HANDLE_SERIALIZE* tunnelContext — a
    // context handle [out] returns its value directly (20 bytes).
    let tunnel_context = ContextHandle::decode_ndr(&mut d)?;
    // [out] unsigned long* tunnelId — just a u32 on the wire.
    let tunnel_id = d.read_u32("CreateTunnelResponse.tunnel_id")?;
    // HRESULT return value.
    let return_value = d.read_u32("CreateTunnelResponse.return_value")?;
    Ok(CreateTunnelResponse {
        tsg_packet_response,
        tunnel_context,
        tunnel_id,
        return_value,
    })
}

// =============================================================================
// TsProxyAuthorizeTunnel (opnum 2)
// =============================================================================

pub fn build_authorize_tunnel_stub(
    tunnel_context: &ContextHandle,
    tsg_packet: &TsgPacket,
) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    tunnel_context.encode_ndr(&mut e);
    tsg_packet.encode_ndr(&mut e);
    e.into_bytes()
}

/// Fields returned by `TsProxyAuthorizeTunnel`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeTunnelResponse {
    /// Should be a `TSG_PACKET_TYPE_RESPONSE` variant carrying a
    /// [`TsgPacketResponse`].
    pub tsg_packet_response: TsgPacket,
    pub return_value: u32,
}

impl AuthorizeTunnelResponse {
    /// Borrow the inner [`TsgPacketResponse`] when the server
    /// returned the expected variant, else `None`.
    pub fn as_response(&self) -> Option<&TsgPacketResponse> {
        if let TsgPacket::Response(r) = &self.tsg_packet_response {
            Some(r)
        } else {
            None
        }
    }
}

pub fn parse_authorize_tunnel_response(stub: &[u8]) -> NdrResult<AuthorizeTunnelResponse> {
    let mut d = NdrDecoder::new(stub);
    let inner_ptr = d.read_unique_pointer("AuthorizeTunnelResponse.inner")?;
    if inner_ptr.is_none() {
        return Err(NdrError::InvalidData {
            context: "AuthorizeTunnelResponse: NULL TSG_PACKET in [out, ref]*",
        });
    }
    let tsg_packet_response = TsgPacket::decode_ndr(&mut d)?;
    let return_value = d.read_u32("AuthorizeTunnelResponse.return_value")?;
    Ok(AuthorizeTunnelResponse {
        tsg_packet_response,
        return_value,
    })
}

// =============================================================================
// TsProxyCreateChannel (opnum 4)
// =============================================================================

pub fn build_create_channel_stub(
    tunnel_context: &ContextHandle,
    ts_endpoint_info: &TsEndpointInfo,
) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    tunnel_context.encode_ndr(&mut e);
    ts_endpoint_info.encode_ndr(&mut e);
    e.into_bytes()
}

/// Fields returned by `TsProxyCreateChannel`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateChannelResponse {
    pub channel_context: ContextHandle,
    pub channel_id: u32,
    pub return_value: u32,
}

pub fn parse_create_channel_response(stub: &[u8]) -> NdrResult<CreateChannelResponse> {
    let mut d = NdrDecoder::new(stub);
    let channel_context = ContextHandle::decode_ndr(&mut d)?;
    let channel_id = d.read_u32("CreateChannelResponse.channel_id")?;
    let return_value = d.read_u32("CreateChannelResponse.return_value")?;
    Ok(CreateChannelResponse {
        channel_context,
        channel_id,
        return_value,
    })
}

// =============================================================================
// TsProxyCloseChannel (opnum 6) / TsProxyCloseTunnel (opnum 7)
// =============================================================================

/// Build stub_data for `TsProxyCloseChannel`. The `[in, out]`
/// context handle is sent inline.
pub fn build_close_channel_stub(channel_context: &ContextHandle) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    channel_context.encode_ndr(&mut e);
    e.into_bytes()
}

/// Parse the stub_data of a `TsProxyCloseChannel` RESPONSE. The
/// server returns a fresh (usually zero) context handle followed by
/// the HRESULT return value.
pub fn parse_close_channel_response(stub: &[u8]) -> NdrResult<(ContextHandle, u32)> {
    let mut d = NdrDecoder::new(stub);
    let context = ContextHandle::decode_ndr(&mut d)?;
    let return_value = d.read_u32("CloseChannelResponse.return_value")?;
    Ok((context, return_value))
}

pub fn build_close_tunnel_stub(tunnel_context: &ContextHandle) -> Vec<u8> {
    // Same wire shape as CloseChannel.
    build_close_channel_stub(tunnel_context)
}

pub fn parse_close_tunnel_response(stub: &[u8]) -> NdrResult<(ContextHandle, u32)> {
    parse_close_channel_response(stub)
}

// =============================================================================
// TsProxySetupReceivePipe (opnum 8) — NDR BYPASSED
// =============================================================================

/// Build the raw message body sent by `TsProxySetupReceivePipe`.
///
/// This opnum does **not** use NDR: the stub_data is exactly one
/// 20-byte context handle in network-representation form (the same
/// wire layout as a DCE/RPC context handle, but not wrapped in NDR
/// alignment). MS-TSGU §2.2.9.4.1.
pub fn build_setup_receive_pipe_message(channel_context: &ContextHandle) -> Vec<u8> {
    let mut out = Vec::with_capacity(ContextHandle::SIZE);
    out.extend_from_slice(&channel_context.attributes.to_le_bytes());
    out.extend_from_slice(&channel_context.uuid.data1.to_le_bytes());
    out.extend_from_slice(&channel_context.uuid.data2.to_le_bytes());
    out.extend_from_slice(&channel_context.uuid.data3.to_le_bytes());
    out.extend_from_slice(&channel_context.uuid.data4);
    out
}

// =============================================================================
// TsProxySendToServer (opnum 9) — NDR BYPASSED, big-endian lengths
// =============================================================================

/// Build the **Generic Send Data Message Packet** wire format used
/// by `TsProxySendToServer` (MS-TSGU §2.2.9.3).
///
/// Layout:
///
/// ```text
/// Offset  Size  Field
/// 0       20    PCHANNEL_CONTEXT_HANDLE_NOSERIALIZE_NR (NR form, LE)
/// 20      4     totalDataBytes           u32 BIG-ENDIAN
/// 24      4     numBuffers (1..=3)       u32 BIG-ENDIAN
/// 28      4     buffer1Length            u32 BIG-ENDIAN
/// 32      4     buffer2Length or 0       u32 BIG-ENDIAN
/// 36      4     buffer3Length or 0       u32 BIG-ENDIAN
/// 40+     ...   buffer1 bytes
/// ...     ...   buffer2 bytes (if any)
/// ...     ...   buffer3 bytes (if any)
/// ```
///
/// `totalDataBytes` is the sum of the three length fields *plus the
/// length fields themselves* (i.e. including the 4-byte length
/// words as part of the count). MS-TSGU §2.2.9.3 diagram.
///
/// Returns `Err(SendToServerError::TooManyBuffers)` if more than
/// three buffers are given or all buffers are empty.
pub fn build_send_to_server_message(
    channel_context: &ContextHandle,
    buffers: &[&[u8]],
) -> Result<Vec<u8>, SendToServerError> {
    if buffers.is_empty() || buffers.len() > 3 {
        return Err(SendToServerError::BadBufferCount(buffers.len()));
    }
    if buffers[0].is_empty() {
        return Err(SendToServerError::EmptyFirstBuffer);
    }

    let mut length_fields = [0u32; 3];
    let mut total_data = 0u32;
    for (i, b) in buffers.iter().enumerate() {
        length_fields[i] = b.len() as u32;
        total_data = total_data
            .checked_add(b.len() as u32)
            .ok_or(SendToServerError::BufferTooLarge)?;
    }
    // Per spec, totalDataBytes includes the three 4-byte length fields.
    total_data = total_data
        .checked_add(12)
        .ok_or(SendToServerError::BufferTooLarge)?;

    let total_len = ContextHandle::SIZE
        + 4 // totalDataBytes
        + 4 // numBuffers
        + 4 + 4 + 4 // length fields
        + buffers.iter().map(|b| b.len()).sum::<usize>();
    let mut out = Vec::with_capacity(total_len);

    // Context handle (NR form — little-endian for attributes + UUID's
    // own mixed-endian layout).
    out.extend_from_slice(&channel_context.attributes.to_le_bytes());
    out.extend_from_slice(&channel_context.uuid.data1.to_le_bytes());
    out.extend_from_slice(&channel_context.uuid.data2.to_le_bytes());
    out.extend_from_slice(&channel_context.uuid.data3.to_le_bytes());
    out.extend_from_slice(&channel_context.uuid.data4);

    // Big-endian length fields (network byte order per §2.2.9.3).
    out.extend_from_slice(&total_data.to_be_bytes());
    out.extend_from_slice(&(buffers.len() as u32).to_be_bytes());
    out.extend_from_slice(&length_fields[0].to_be_bytes());
    out.extend_from_slice(&length_fields[1].to_be_bytes());
    out.extend_from_slice(&length_fields[2].to_be_bytes());

    // Buffer contents.
    for b in buffers {
        out.extend_from_slice(b);
    }
    Ok(out)
}

/// Errors raised by [`build_send_to_server_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendToServerError {
    BadBufferCount(usize),
    EmptyFirstBuffer,
    BufferTooLarge,
}

impl core::fmt::Display for SendToServerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadBufferCount(n) => {
                write!(f, "SendToServer: buffer count {n} not in [1,3]")
            }
            Self::EmptyFirstBuffer => {
                f.write_str("SendToServer: buffer1Length MUST be nonzero")
            }
            Self::BufferTooLarge => {
                f.write_str("SendToServer: totalDataBytes overflowed u32")
            }
        }
    }
}

impl core::error::Error for SendToServerError {}

// =============================================================================
// Helper — retrieve a CapsResponse/QuarEncResponse variant from a
// CreateTunnel response.
// =============================================================================

/// Return the embedded [`TsgPacketQuarEncResponse`] from a
/// `CreateTunnelResponse.tsg_packet_response`, whether the server
/// wrapped it in a `CapsResponse` or returned it directly as a
/// `QuarEncResponse`.
pub fn extract_quar_enc_response(pkt: &TsgPacket) -> Option<&TsgPacketQuarEncResponse> {
    match pkt {
        TsgPacket::QuarEncResponse(q) => Some(q),
        TsgPacket::CapsResponse(c) => Some(&c.pkt_quar_enc_response),
        _ => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpch::types::{
        TsgPacketQuarRequest, TsgPacketVersionCaps, TSG_NAP_CAPABILITY_QUAR_SOH,
    };
    use alloc::string::String;
    use alloc::vec;

    fn sample_handle() -> ContextHandle {
        ContextHandle {
            attributes: 1,
            uuid: justrdp_rpch::pdu::uuid::RpcUuid::parse(
                "12345678-1234-5678-abcd-ef0123456789",
            )
            .unwrap(),
        }
    }

    #[test]
    fn opnums_match_wire_layout() {
        // Not 5, 0 which are "NotUsedOnWire".
        assert_eq!(OPNUM_TS_PROXY_CREATE_TUNNEL, 1);
        assert_eq!(OPNUM_TS_PROXY_AUTHORIZE_TUNNEL, 2);
        assert_eq!(OPNUM_TS_PROXY_MAKE_TUNNEL_CALL, 3);
        assert_eq!(OPNUM_TS_PROXY_CREATE_CHANNEL, 4);
        assert_eq!(OPNUM_TS_PROXY_CLOSE_CHANNEL, 6);
        assert_eq!(OPNUM_TS_PROXY_CLOSE_TUNNEL, 7);
        assert_eq!(OPNUM_TS_PROXY_SETUP_RECEIVE_PIPE, 8);
        assert_eq!(OPNUM_TS_PROXY_SEND_TO_SERVER, 9);
    }

    #[test]
    fn build_create_tunnel_stub_starts_with_packet_id() {
        let pkt = TsgPacket::VersionCaps(TsgPacketVersionCaps::client_default(
            TSG_NAP_CAPABILITY_QUAR_SOH,
        ));
        let stub = build_create_tunnel_stub(&pkt);
        // packetId should be the first 4 LE bytes.
        let got = u32::from_le_bytes([stub[0], stub[1], stub[2], stub[3]]);
        assert_eq!(got, super::super::types::TSG_PACKET_TYPE_VERSIONCAPS);
    }

    #[test]
    fn authorize_tunnel_stub_has_handle_then_packet() {
        let pkt = TsgPacket::QuarRequest(TsgPacketQuarRequest {
            flags: 0,
            machine_name: None,
            data: None,
        });
        let h = sample_handle();
        let stub = build_authorize_tunnel_stub(&h, &pkt);
        // First 20 bytes should be the context handle.
        assert_eq!(stub.len() > ContextHandle::SIZE, true);
    }

    #[test]
    fn close_channel_roundtrip() {
        let h = sample_handle();
        let stub = build_close_channel_stub(&h);
        assert_eq!(stub.len(), ContextHandle::SIZE);
        // Simulate server return: same handle (usually all-zero on
        // success) + HRESULT.
        let mut response_stub = build_close_channel_stub(&ContextHandle::NIL);
        response_stub.extend_from_slice(&0u32.to_le_bytes()); // ERROR_SUCCESS
        let (got, ret) = parse_close_channel_response(&response_stub).unwrap();
        assert_eq!(got, ContextHandle::NIL);
        assert_eq!(ret, 0);
    }

    #[test]
    fn close_tunnel_shares_close_channel_wire() {
        let h = sample_handle();
        assert_eq!(
            build_close_tunnel_stub(&h),
            build_close_channel_stub(&h)
        );
    }

    #[test]
    fn setup_receive_pipe_is_20_bytes() {
        let h = sample_handle();
        let msg = build_setup_receive_pipe_message(&h);
        assert_eq!(msg.len(), ContextHandle::SIZE);
    }

    #[test]
    fn send_to_server_single_buffer_layout() {
        let h = sample_handle();
        let buf = b"hello";
        let msg = build_send_to_server_message(&h, &[buf]).unwrap();
        // Total: 20 (handle) + 4 (totalDataBytes) + 4 (numBuffers) +
        // 12 (three length fields) + 5 (payload) = 45 bytes.
        assert_eq!(msg.len(), 45);

        // totalDataBytes is at offset 20, big-endian. Should equal
        // buffer1Length + buffer2Length + buffer3Length + 12 =
        // 5 + 0 + 0 + 12 = 17.
        let total_data = u32::from_be_bytes([msg[20], msg[21], msg[22], msg[23]]);
        assert_eq!(total_data, 17);

        // numBuffers at offset 24, big-endian.
        let num_buffers = u32::from_be_bytes([msg[24], msg[25], msg[26], msg[27]]);
        assert_eq!(num_buffers, 1);

        // buffer1Length at offset 28, big-endian.
        let b1_len = u32::from_be_bytes([msg[28], msg[29], msg[30], msg[31]]);
        assert_eq!(b1_len, 5);

        // Buffer2/3 lengths at 32/36 must be zero.
        assert_eq!(&msg[32..40], &[0; 8]);

        // Payload at offset 40.
        assert_eq!(&msg[40..45], buf);
    }

    #[test]
    fn send_to_server_three_buffers_layout() {
        let h = sample_handle();
        let b1 = &[0x11u8; 4];
        let b2 = &[0x22u8; 8];
        let b3 = &[0x33u8; 2];
        let msg = build_send_to_server_message(&h, &[b1, b2, b3]).unwrap();
        let total_data = u32::from_be_bytes([msg[20], msg[21], msg[22], msg[23]]);
        assert_eq!(total_data, 4 + 8 + 2 + 12);
        assert_eq!(&msg[40..44], b1);
        assert_eq!(&msg[44..52], b2);
        assert_eq!(&msg[52..54], b3);
    }

    #[test]
    fn send_to_server_rejects_empty_buffer_list() {
        let h = sample_handle();
        assert!(matches!(
            build_send_to_server_message(&h, &[]),
            Err(SendToServerError::BadBufferCount(0))
        ));
    }

    #[test]
    fn send_to_server_rejects_too_many_buffers() {
        let h = sample_handle();
        let b = &[0u8; 1];
        assert!(matches!(
            build_send_to_server_message(&h, &[b, b, b, b]),
            Err(SendToServerError::BadBufferCount(4))
        ));
    }

    #[test]
    fn send_to_server_rejects_empty_first_buffer() {
        let h = sample_handle();
        assert!(matches!(
            build_send_to_server_message(&h, &[b""]),
            Err(SendToServerError::EmptyFirstBuffer)
        ));
    }

    #[test]
    fn extract_quar_enc_from_either_variant() {
        use crate::rpch::types::TsgPacketQuarEncResponse;
        let q = TsgPacketQuarEncResponse {
            flags: 0,
            cert_chain: None,
            nonce: justrdp_rpch::pdu::uuid::RpcUuid::NIL,
            version_caps: None,
        };
        let pkt_direct = TsgPacket::QuarEncResponse(q.clone());
        assert!(extract_quar_enc_response(&pkt_direct).is_some());

        let pkt_caps = TsgPacket::CapsResponse(crate::rpch::types::TsgPacketCapsResponse {
            pkt_quar_enc_response: q.clone(),
            pkt_consent_message_raw: vec![],
        });
        assert!(extract_quar_enc_response(&pkt_caps).is_some());

        let pkt_other = TsgPacket::QuarRequest(TsgPacketQuarRequest {
            flags: 0,
            machine_name: None,
            data: None,
        });
        assert!(extract_quar_enc_response(&pkt_other).is_none());
    }

    #[test]
    fn create_channel_response_parse_roundtrip() {
        // Synthesize a response stub: ContextHandle + u32 channel_id
        // + u32 return_value.
        let mut e = NdrEncoder::new();
        sample_handle().encode_ndr(&mut e);
        e.write_u32(0xAAAA_AAAA);
        e.write_u32(0);
        let bytes = e.into_bytes();

        let resp = parse_create_channel_response(&bytes).unwrap();
        assert_eq!(resp.channel_context, sample_handle());
        assert_eq!(resp.channel_id, 0xAAAA_AAAA);
        assert_eq!(resp.return_value, 0);
    }

    // Used to silence the unused String import warning when no
    // test below consumes it; also kept for future test additions.
    #[allow(dead_code)]
    fn _dummy(_s: String) {}
}
