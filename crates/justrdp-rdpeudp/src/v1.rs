#![forbid(unsafe_code)]

//! MS-RDPEUDP v1 PDU structures (§2.2).
//!
//! Every v1 datagram begins with an [`RdpUdpFecHeader`], followed by
//! zero or more sub-structures whose presence is gated by the bits
//! in the header's `uFlags` field. Sub-structures appear on the wire
//! in the canonical order defined by §3.1.5.1.1 (SYN construction)
//! and §3.1.5 (Data Transfer). The PDU layer in this module only
//! handles bytes in/out — the state machine that decides *which*
//! flags to set lives higher up.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeErrorKind, DecodeResult, Encode, EncodeError, EncodeResult,
    ReadCursor, WriteCursor,
};

// =============================================================================
// Flag constants (§2.2.2.1)
// =============================================================================

/// `uFlags` bits for [`RdpUdpFecHeader`].
pub const RDPUDP_FLAG_SYN: u16 = 0x0001;
pub const RDPUDP_FLAG_FIN: u16 = 0x0002;
pub const RDPUDP_FLAG_ACK: u16 = 0x0004;
pub const RDPUDP_FLAG_DATA: u16 = 0x0008;
pub const RDPUDP_FLAG_FEC: u16 = 0x0010;
pub const RDPUDP_FLAG_CN: u16 = 0x0020;
pub const RDPUDP_FLAG_CWR: u16 = 0x0040;
pub const RDPUDP_FLAG_SACK_OPTION: u16 = 0x0080;
pub const RDPUDP_FLAG_ACK_OF_ACKS: u16 = 0x0100;
pub const RDPUDP_FLAG_SYNLOSSY: u16 = 0x0200;
pub const RDPUDP_FLAG_ACKDELAYED: u16 = 0x0400;
pub const RDPUDP_FLAG_CORRELATION_ID: u16 = 0x0800;
pub const RDPUDP_FLAG_SYNEX: u16 = 0x1000;

/// Sentinel value used in `snSourceAck` of a SYN datagram (§3.1.5.1.1
/// step 1 — "the initial sequence number MUST be set to minus one").
pub const RDPUDP_INITIAL_SOURCE_ACK: u32 = u32::MAX;

// =============================================================================
// Protocol versions (§2.2.2.9)
// =============================================================================

/// `uUdpVer` values transported inside [`SynDataExPayload`].
pub const RDPUDP_PROTOCOL_VERSION_1: u16 = 0x0001;
pub const RDPUDP_PROTOCOL_VERSION_2: u16 = 0x0002;
pub const RDPUDP_PROTOCOL_VERSION_3: u16 = 0x0101;

/// `uSynExFlags` bit: `uUdpVer` carries a valid value (§2.2.2.9).
pub const RDPUDP_VERSION_INFO_VALID: u16 = 0x0001;

// =============================================================================
// SYN MTU range (§2.2.2.5)
// =============================================================================

pub const RDPUDP_MIN_MTU: u16 = 1132;
pub const RDPUDP_MAX_MTU: u16 = 1232;

// =============================================================================
// ACK vector (§2.2.2.7 + §2.2.1.1)
// =============================================================================

/// 2-bit state of each element in `AckVector` (§2.2.1.1).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorElementState {
    DatagramReceived = 0,
    DatagramReserved1 = 1,
    DatagramReserved2 = 2,
    DatagramNotYetReceived = 3,
}

impl VectorElementState {
    pub const fn from_bits(v: u8) -> Self {
        match v & 0x3 {
            0 => Self::DatagramReceived,
            1 => Self::DatagramReserved1,
            2 => Self::DatagramReserved2,
            _ => Self::DatagramNotYetReceived,
        }
    }
}

/// One `AckVectorElement` — a 2-bit state plus a 6-bit run length
/// encoded into a single byte (§2.2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckVectorElement {
    pub state: VectorElementState,
    /// Number of consecutive datagrams covered by this element. The
    /// wire encoding stores `run_length - 1` in the low 6 bits, so
    /// `run_length` ranges from 1 through 64 inclusive.
    pub run_length: u8,
}

impl AckVectorElement {
    pub const fn new(state: VectorElementState, run_length: u8) -> Self {
        debug_assert!(run_length >= 1 && run_length <= 64);
        Self { state, run_length }
    }

    pub fn to_byte(self) -> u8 {
        ((self.state as u8) << 6) | ((self.run_length - 1) & 0x3F)
    }

    pub fn from_byte(b: u8) -> Self {
        Self {
            state: VectorElementState::from_bits(b >> 6),
            run_length: (b & 0x3F) + 1,
        }
    }
}

/// Upper bound on `uAckVectorSize` (§2.2.2.7 — "MUST NOT exceed 2048").
pub const RDPUDP_MAX_ACK_VECTOR_SIZE: usize = 2048;

// =============================================================================
// RdpUdpFecHeader — §2.2.2.1
// =============================================================================

/// Mandatory 8-byte header on every v1 datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpUdpFecHeader {
    /// Highest Source Packet sequence number seen from the peer. The
    /// SYN datagram MUST set this to [`RDPUDP_INITIAL_SOURCE_ACK`].
    pub sn_source_ack: u32,
    /// Number of datagrams the receiver can buffer.
    pub u_receive_window_size: u16,
    /// Bitmask of `RDPUDP_FLAG_*` values indicating which optional
    /// sub-structures follow.
    pub u_flags: u16,
}

pub const RDPUDP_FEC_HEADER_SIZE: usize = 8;

impl Encode for RdpUdpFecHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.sn_source_ack, "snSourceAck")?;
        dst.write_u16_le(self.u_receive_window_size, "uReceiveWindowSize")?;
        dst.write_u16_le(self.u_flags, "uFlags")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP_FEC_HEADER"
    }

    fn size(&self) -> usize {
        RDPUDP_FEC_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for RdpUdpFecHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let sn_source_ack = src.read_u32_le("snSourceAck")?;
        let u_receive_window_size = src.read_u16_le("uReceiveWindowSize")?;
        let u_flags = src.read_u16_le("uFlags")?;
        Ok(Self {
            sn_source_ack,
            u_receive_window_size,
            u_flags,
        })
    }
}

// =============================================================================
// SynDataPayload — §2.2.2.5
// =============================================================================

/// Follows [`RdpUdpFecHeader`] whenever `RDPUDP_FLAG_SYN` is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynDataPayload {
    pub sn_initial_sequence_number: u32,
    /// Upstream MTU. MUST be in `[RDPUDP_MIN_MTU, RDPUDP_MAX_MTU]`.
    pub u_up_stream_mtu: u16,
    /// Downstream MTU. MUST be in `[RDPUDP_MIN_MTU, RDPUDP_MAX_MTU]`.
    pub u_down_stream_mtu: u16,
}

pub const SYN_DATA_PAYLOAD_SIZE: usize = 8;

impl Encode for SynDataPayload {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if !valid_mtu(self.u_up_stream_mtu) || !valid_mtu(self.u_down_stream_mtu) {
            return Err(EncodeError::invalid_value(
                "RDPUDP_SYNDATA_PAYLOAD",
                "uUpStreamMtu/uDownStreamMtu out of [1132, 1232]",
            ));
        }
        dst.write_u32_le(self.sn_initial_sequence_number, "snInitialSequenceNumber")?;
        dst.write_u16_le(self.u_up_stream_mtu, "uUpStreamMtu")?;
        dst.write_u16_le(self.u_down_stream_mtu, "uDownStreamMtu")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP_SYNDATA_PAYLOAD"
    }

    fn size(&self) -> usize {
        SYN_DATA_PAYLOAD_SIZE
    }
}

impl<'de> Decode<'de> for SynDataPayload {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let sn = src.read_u32_le("snInitialSequenceNumber")?;
        let up = src.read_u16_le("uUpStreamMtu")?;
        let down = src.read_u16_le("uDownStreamMtu")?;
        if !valid_mtu(up) || !valid_mtu(down) {
            return Err(DecodeError::new(
                "RDPUDP_SYNDATA_PAYLOAD",
                DecodeErrorKind::InvalidValue {
                    field: "uUpStreamMtu/uDownStreamMtu",
                },
            ));
        }
        Ok(Self {
            sn_initial_sequence_number: sn,
            u_up_stream_mtu: up,
            u_down_stream_mtu: down,
        })
    }
}

fn valid_mtu(mtu: u16) -> bool {
    (RDPUDP_MIN_MTU..=RDPUDP_MAX_MTU).contains(&mtu)
}

// =============================================================================
// AckVectorHeader — §2.2.2.7
// =============================================================================

/// Variable-length `RDPUDP_ACK_VECTOR_HEADER`, DWORD-aligned on the
/// wire. Present when `RDPUDP_FLAG_ACK` is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckVectorHeader {
    pub ack_vector: Vec<AckVectorElement>,
}

impl AckVectorHeader {
    pub const fn new(ack_vector: Vec<AckVectorElement>) -> Self {
        Self { ack_vector }
    }

    /// Return the number of trailing zero pad bytes required to land
    /// the entire structure on a 4-byte boundary.
    pub fn padding_bytes(&self) -> usize {
        let unpadded = 2 + self.ack_vector.len();
        (4 - (unpadded % 4)) % 4
    }
}

impl Encode for AckVectorHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.ack_vector.len() > RDPUDP_MAX_ACK_VECTOR_SIZE {
            return Err(EncodeError::invalid_value(
                "RDPUDP_ACK_VECTOR_HEADER",
                "uAckVectorSize exceeds 2048",
            ));
        }
        dst.write_u16_le(self.ack_vector.len() as u16, "uAckVectorSize")?;
        for el in &self.ack_vector {
            dst.write_u8(el.to_byte(), "AckVector")?;
        }
        for _ in 0..self.padding_bytes() {
            dst.write_u8(0, "Padding")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP_ACK_VECTOR_HEADER"
    }

    fn size(&self) -> usize {
        2 + self.ack_vector.len() + self.padding_bytes()
    }
}

impl<'de> Decode<'de> for AckVectorHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let n = src.read_u16_le("uAckVectorSize")? as usize;
        if n > RDPUDP_MAX_ACK_VECTOR_SIZE {
            return Err(DecodeError::new(
                "RDPUDP_ACK_VECTOR_HEADER",
                DecodeErrorKind::InvalidValue {
                    field: "uAckVectorSize",
                },
            ));
        }
        let bytes = src.read_slice(n, "AckVector")?;
        let ack_vector = bytes.iter().map(|b| AckVectorElement::from_byte(*b)).collect::<Vec<_>>();

        // Consume DWORD alignment padding.
        let unpadded = 2 + n;
        let pad = (4 - (unpadded % 4)) % 4;
        let _ = src.read_slice(pad, "Padding")?;

        Ok(Self { ack_vector })
    }
}

// =============================================================================
// AckOfAcksHeader — §2.2.2.6
// =============================================================================

/// Present when `RDPUDP_FLAG_ACK_OF_ACKS` is set (which requires
/// `RDPUDP_FLAG_ACK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckOfAcksHeader {
    /// Receiver resets its ACK vector so it only covers sequence
    /// numbers strictly greater than this value.
    pub sn_reset_seq_num: u32,
}

pub const ACK_OF_ACKS_HEADER_SIZE: usize = 4;

impl Encode for AckOfAcksHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.sn_reset_seq_num, "snResetSeqNum")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP_ACK_OF_ACKVECTOR_HEADER"
    }

    fn size(&self) -> usize {
        ACK_OF_ACKS_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for AckOfAcksHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let sn_reset_seq_num = src.read_u32_le("snResetSeqNum")?;
        Ok(Self { sn_reset_seq_num })
    }
}

// =============================================================================
// SourcePayloadHeader — §2.2.2.4
// =============================================================================

/// Present when `RDPUDP_FLAG_DATA` is set and `RDPUDP_FLAG_FEC` is
/// NOT set. Immediately followed by the raw payload bytes, whose
/// length is implicit (the rest of the UDP datagram).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePayloadHeader {
    pub sn_coded: u32,
    pub sn_source_start: u32,
}

pub const SOURCE_PAYLOAD_HEADER_SIZE: usize = 8;

impl Encode for SourcePayloadHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.sn_coded, "snCoded")?;
        dst.write_u32_le(self.sn_source_start, "snSourceStart")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP_SOURCE_PAYLOAD_HEADER"
    }

    fn size(&self) -> usize {
        SOURCE_PAYLOAD_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for SourcePayloadHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let sn_coded = src.read_u32_le("snCoded")?;
        let sn_source_start = src.read_u32_le("snSourceStart")?;
        Ok(Self {
            sn_coded,
            sn_source_start,
        })
    }
}

// =============================================================================
// FecPayloadHeader — §2.2.2.2
// =============================================================================

/// Present when both `RDPUDP_FLAG_DATA` and `RDPUDP_FLAG_FEC` are set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecPayloadHeader {
    pub sn_coded: u32,
    pub sn_source_start: u32,
    /// Added to `sn_source_start` to yield the last Source Packet
    /// sequence number included in this FEC operation (0 = single
    /// source packet).
    pub u_range: u8,
    /// Opaque FEC engine index.
    pub u_fec_index: u8,
    // 2 bytes `uPadding` follow on the wire — MUST be zero on encode,
    // ignored on decode.
}

pub const FEC_PAYLOAD_HEADER_SIZE: usize = 12;

impl Encode for FecPayloadHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.sn_coded, "snCoded")?;
        dst.write_u32_le(self.sn_source_start, "snSourceStart")?;
        dst.write_u8(self.u_range, "uRange")?;
        dst.write_u8(self.u_fec_index, "uFecIndex")?;
        dst.write_u16_le(0, "uPadding")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP_FEC_PAYLOAD_HEADER"
    }

    fn size(&self) -> usize {
        FEC_PAYLOAD_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for FecPayloadHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let sn_coded = src.read_u32_le("snCoded")?;
        let sn_source_start = src.read_u32_le("snSourceStart")?;
        let u_range = src.read_u8("uRange")?;
        let u_fec_index = src.read_u8("uFecIndex")?;
        let _padding = src.read_u16_le("uPadding")?;
        Ok(Self {
            sn_coded,
            sn_source_start,
            u_range,
            u_fec_index,
        })
    }
}

// =============================================================================
// CorrelationIdPayload — §2.2.2.8
// =============================================================================

/// Present when `RDPUDP_FLAG_CORRELATION_ID` is set. Client-to-server
/// SYN only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationIdPayload {
    /// 16-byte correlation identifier, transmitted as a flat
    /// big-endian byte array (§2.2.2.8 — not a Windows GUID layout).
    /// Constraints:
    /// - `u_correlation_id[0]` MUST NOT be `0x00` or `0xF4`.
    /// - No byte MAY equal `0x0D`.
    pub u_correlation_id: [u8; 16],
    // 16 bytes `uReserved` follow on the wire — all zero on encode,
    // tolerated on decode.
}

pub const CORRELATION_ID_PAYLOAD_SIZE: usize = 32;

impl CorrelationIdPayload {
    /// Return `true` if `id` satisfies the spec constraints on byte
    /// values (§2.2.2.8).
    pub fn valid_id(id: &[u8; 16]) -> bool {
        if id[0] == 0x00 || id[0] == 0xF4 {
            return false;
        }
        !id.contains(&0x0D)
    }
}

impl Encode for CorrelationIdPayload {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if !Self::valid_id(&self.u_correlation_id) {
            return Err(EncodeError::invalid_value(
                "RDPUDP_CORRELATION_ID_PAYLOAD",
                "uCorrelationId violates byte-value constraint",
            ));
        }
        dst.write_slice(&self.u_correlation_id, "uCorrelationId")?;
        dst.write_slice(&[0u8; 16], "uReserved")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP_CORRELATION_ID_PAYLOAD"
    }

    fn size(&self) -> usize {
        CORRELATION_ID_PAYLOAD_SIZE
    }
}

impl<'de> Decode<'de> for CorrelationIdPayload {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let id_slice = src.read_slice(16, "uCorrelationId")?;
        let mut u_correlation_id = [0u8; 16];
        u_correlation_id.copy_from_slice(id_slice);
        let _reserved = src.read_slice(16, "uReserved")?;
        Ok(Self { u_correlation_id })
    }
}

// =============================================================================
// SynDataExPayload — §2.2.2.9
// =============================================================================

/// Present when `RDPUDP_FLAG_SYNEX` is set on a SYN or SYN+ACK.
///
/// The `cookie_hash` field is present only when `u_udp_ver ==
/// RDPUDP_PROTOCOL_VERSION_3` on a client→server SYN and contains a
/// SHA-256 hash of the MS-RDPBCGR `securityCookie` (§2.2.15.1). The
/// PDU layer treats it as an opaque 32-byte blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynDataExPayload {
    pub u_syn_ex_flags: u16,
    pub u_udp_ver: u16,
    pub cookie_hash: Option<[u8; 32]>,
}

pub const SYN_DATA_EX_PAYLOAD_FIXED_SIZE: usize = 4;
pub const SYN_DATA_EX_PAYLOAD_WITH_COOKIE_SIZE: usize = 36;

impl Encode for SynDataExPayload {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.cookie_hash.is_some() {
            // §2.2.2.9: cookieHash is only meaningful when the
            // version info is actually valid AND the version is v3.
            if self.u_udp_ver != RDPUDP_PROTOCOL_VERSION_3 {
                return Err(EncodeError::invalid_value(
                    "RDPUDP_SYNDATAEX_PAYLOAD",
                    "cookieHash present but uUdpVer != PROTOCOL_VERSION_3",
                ));
            }
            if self.u_syn_ex_flags & RDPUDP_VERSION_INFO_VALID == 0 {
                return Err(EncodeError::invalid_value(
                    "RDPUDP_SYNDATAEX_PAYLOAD",
                    "cookieHash present but RDPUDP_VERSION_INFO_VALID clear",
                ));
            }
        }
        dst.write_u16_le(self.u_syn_ex_flags, "uSynExFlags")?;
        dst.write_u16_le(self.u_udp_ver, "uUdpVer")?;
        if let Some(hash) = &self.cookie_hash {
            dst.write_slice(hash, "cookieHash")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP_SYNDATAEX_PAYLOAD"
    }

    fn size(&self) -> usize {
        if self.cookie_hash.is_some() {
            SYN_DATA_EX_PAYLOAD_WITH_COOKIE_SIZE
        } else {
            SYN_DATA_EX_PAYLOAD_FIXED_SIZE
        }
    }
}

impl SynDataExPayload {
    /// Decode a SYNDATAEX payload. The caller must indicate whether
    /// the 32-byte `cookie_hash` is expected, because its presence is
    /// gated by the direction of the datagram and by `u_udp_ver`
    /// — context the PDU stream alone cannot recover.
    pub fn decode_with_cookie<'de>(
        src: &mut ReadCursor<'de>,
        expect_cookie_hash: bool,
    ) -> DecodeResult<Self> {
        let u_syn_ex_flags = src.read_u16_le("uSynExFlags")?;
        let u_udp_ver = src.read_u16_le("uUdpVer")?;
        let cookie_hash = if expect_cookie_hash {
            let slice = src.read_slice(32, "cookieHash")?;
            let mut h = [0u8; 32];
            h.copy_from_slice(slice);
            Some(h)
        } else {
            None
        };
        Ok(Self {
            u_syn_ex_flags,
            u_udp_ver,
            cookie_hash,
        })
    }

    /// Decode a client→server SYN SYNDATAEX payload, auto-detecting
    /// the optional `cookieHash` from the version field.
    ///
    /// Per §2.2.2.9 the hash is present iff
    /// `uUdpVer == RDPUDP_PROTOCOL_VERSION_3` AND the
    /// `RDPUDP_VERSION_INFO_VALID` flag is set. The server uses this
    /// entry point because the SYN+ACK (server→client) never carries
    /// a cookie — asymmetry the PDU alone cannot infer.
    pub fn decode_client_syn<'de>(
        src: &mut ReadCursor<'de>,
    ) -> DecodeResult<Self> {
        let u_syn_ex_flags = src.read_u16_le("uSynExFlags")?;
        let u_udp_ver = src.read_u16_le("uUdpVer")?;
        let has_cookie = u_udp_ver == RDPUDP_PROTOCOL_VERSION_3
            && (u_syn_ex_flags & RDPUDP_VERSION_INFO_VALID) != 0;
        let cookie_hash = if has_cookie {
            let slice = src.read_slice(32, "cookieHash")?;
            let mut h = [0u8; 32];
            h.copy_from_slice(slice);
            Some(h)
        } else {
            None
        };
        Ok(Self {
            u_syn_ex_flags,
            u_udp_ver,
            cookie_hash,
        })
    }
}

// =============================================================================
// PayloadPrefix — §2.2.2.3
// =============================================================================

/// 2-byte length prefix prepended to each source payload before FEC
/// encoding and visible in FEC-recovered data streams (§2.2.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadPrefix {
    /// Length in bytes of the data payload that follows this prefix.
    pub cb_payload_size: u16,
}

pub const PAYLOAD_PREFIX_SIZE: usize = 2;

impl Encode for PayloadPrefix {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.cb_payload_size, "cbPayloadSize")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP_PAYLOAD_PREFIX"
    }

    fn size(&self) -> usize {
        PAYLOAD_PREFIX_SIZE
    }
}

impl<'de> Decode<'de> for PayloadPrefix {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cb_payload_size = src.read_u16_le("cbPayloadSize")?;
        Ok(Self { cb_payload_size })
    }
}

// =============================================================================
// SYN datagram padding (§3.1.5.1.1 step 6)
// =============================================================================

/// Return the number of trailing zero bytes needed to pad a SYN
/// datagram of `total_written` bytes up to `min(up_mtu, down_mtu)`.
/// Returns 0 if the datagram is already at or beyond the target.
pub fn syn_padding_size(total_written: usize, up_mtu: u16, down_mtu: u16) -> usize {
    let target = core::cmp::min(up_mtu, down_mtu) as usize;
    target.saturating_sub(total_written)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use justrdp_core::{encode_vec, ReadCursor};

    // ── RdpUdpFecHeader ──

    #[test]
    fn fec_header_roundtrip() {
        let hdr = RdpUdpFecHeader {
            sn_source_ack: 0xDEADBEEF,
            u_receive_window_size: 0x1234,
            u_flags: RDPUDP_FLAG_DATA | RDPUDP_FLAG_ACK,
        };
        let bytes = encode_vec(&hdr).unwrap();
        assert_eq!(bytes, vec![0xEF, 0xBE, 0xAD, 0xDE, 0x34, 0x12, 0x0C, 0x00]);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = RdpUdpFecHeader::decode(&mut cur).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn fec_header_syn_sentinel() {
        let hdr = RdpUdpFecHeader {
            sn_source_ack: RDPUDP_INITIAL_SOURCE_ACK,
            u_receive_window_size: 64,
            u_flags: RDPUDP_FLAG_SYN,
        };
        let bytes = encode_vec(&hdr).unwrap();
        assert_eq!(&bytes[..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    // ── SynDataPayload ──

    #[test]
    fn syn_data_payload_roundtrip() {
        let pdu = SynDataPayload {
            sn_initial_sequence_number: 0xCAFE_F00D,
            u_up_stream_mtu: 1200,
            u_down_stream_mtu: 1132,
        };
        let bytes = encode_vec(&pdu).unwrap();
        let mut cur = ReadCursor::new(&bytes);
        let decoded = SynDataPayload::decode(&mut cur).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(bytes.len(), SYN_DATA_PAYLOAD_SIZE);
    }

    #[test]
    fn syn_data_payload_rejects_mtu_below_min() {
        let pdu = SynDataPayload {
            sn_initial_sequence_number: 0,
            u_up_stream_mtu: 1131,
            u_down_stream_mtu: 1200,
        };
        assert!(encode_vec(&pdu).is_err());
    }

    #[test]
    fn syn_data_payload_rejects_mtu_above_max() {
        let pdu = SynDataPayload {
            sn_initial_sequence_number: 0,
            u_up_stream_mtu: 1200,
            u_down_stream_mtu: 1233,
        };
        assert!(encode_vec(&pdu).is_err());
    }

    #[test]
    fn syn_data_payload_boundary_accepts_min_and_max() {
        for mtu in [RDPUDP_MIN_MTU, RDPUDP_MAX_MTU] {
            let pdu = SynDataPayload {
                sn_initial_sequence_number: 1,
                u_up_stream_mtu: mtu,
                u_down_stream_mtu: mtu,
            };
            let bytes = encode_vec(&pdu).unwrap();
            assert_eq!(bytes.len(), 8);
        }
    }

    // ── AckVectorElement ──

    #[test]
    fn ack_vector_element_encoding() {
        // state=RECEIVED (00), run=4 → (4-1)=3 → byte = 0x03.
        let el = AckVectorElement::new(VectorElementState::DatagramReceived, 4);
        assert_eq!(el.to_byte(), 0x03);
        // state=NOT_YET_RECEIVED (11), run=5 → (5-1)=4 → byte = 0xC4.
        let el = AckVectorElement::new(VectorElementState::DatagramNotYetReceived, 5);
        assert_eq!(el.to_byte(), 0xC4);
        // Roundtrip every legal byte.
        for b in 0u8..=255 {
            let el = AckVectorElement::from_byte(b);
            assert_eq!(el.to_byte(), b);
        }
    }

    #[test]
    fn ack_vector_element_reserved_states_preserved() {
        for raw in [0x40u8, 0x80u8] {
            let el = AckVectorElement::from_byte(raw);
            assert!(matches!(
                el.state,
                VectorElementState::DatagramReserved1 | VectorElementState::DatagramReserved2
            ));
            assert_eq!(el.to_byte(), raw);
        }
    }

    // ── AckVectorHeader ──

    #[test]
    fn ack_vector_header_dword_aligned_encode_and_decode() {
        // 3 elements → 2 + 3 = 5 → pad with 3 zero bytes.
        let hdr = AckVectorHeader::new(vec![
            AckVectorElement::new(VectorElementState::DatagramReceived, 4),
            AckVectorElement::new(VectorElementState::DatagramReceived, 2),
            AckVectorElement::new(VectorElementState::DatagramNotYetReceived, 1),
        ]);
        assert_eq!(hdr.padding_bytes(), 3);
        let bytes = encode_vec(&hdr).unwrap();
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes.len() % 4, 0);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = AckVectorHeader::decode(&mut cur).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn ack_vector_header_empty_has_two_byte_padding() {
        let hdr = AckVectorHeader::new(vec![]);
        assert_eq!(hdr.padding_bytes(), 2);
        let bytes = encode_vec(&hdr).unwrap();
        assert_eq!(bytes, vec![0, 0, 0, 0]);
    }

    #[test]
    fn ack_vector_header_rejects_oversize() {
        let hdr = AckVectorHeader::new(
            (0..(RDPUDP_MAX_ACK_VECTOR_SIZE + 1))
                .map(|_| AckVectorElement::new(VectorElementState::DatagramReceived, 1))
                .collect(),
        );
        assert!(encode_vec(&hdr).is_err());
    }

    // ── AckOfAcksHeader ──

    #[test]
    fn ack_of_acks_roundtrip() {
        let pdu = AckOfAcksHeader {
            sn_reset_seq_num: 0x1234_5678,
        };
        let bytes = encode_vec(&pdu).unwrap();
        assert_eq!(bytes, vec![0x78, 0x56, 0x34, 0x12]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(AckOfAcksHeader::decode(&mut cur).unwrap(), pdu);
    }

    // ── SourcePayloadHeader ──

    #[test]
    fn source_payload_header_roundtrip() {
        let pdu = SourcePayloadHeader {
            sn_coded: 0xAABB_CCDD,
            sn_source_start: 0x1122_3344,
        };
        let bytes = encode_vec(&pdu).unwrap();
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(SourcePayloadHeader::decode(&mut cur).unwrap(), pdu);
    }

    // ── FecPayloadHeader ──

    #[test]
    fn fec_payload_header_roundtrip() {
        let pdu = FecPayloadHeader {
            sn_coded: 0xFD1A47EC,
            sn_source_start: 0xFD1A47EC,
            u_range: 0x10,
            u_fec_index: 0x01,
        };
        let bytes = encode_vec(&pdu).unwrap();
        assert_eq!(
            bytes,
            vec![0xEC, 0x47, 0x1A, 0xFD, 0xEC, 0x47, 0x1A, 0xFD, 0x10, 0x01, 0x00, 0x00],
        );
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(FecPayloadHeader::decode(&mut cur).unwrap(), pdu);
    }

    // ── CorrelationIdPayload ──

    #[test]
    fn correlation_id_roundtrip_and_reserved_zero() {
        let id = [0x11u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 17];
        let pdu = CorrelationIdPayload {
            u_correlation_id: id,
        };
        let bytes = encode_vec(&pdu).unwrap();
        assert_eq!(bytes.len(), CORRELATION_ID_PAYLOAD_SIZE);
        assert_eq!(&bytes[..16], &id[..]);
        assert_eq!(&bytes[16..], &[0u8; 16][..]);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = CorrelationIdPayload::decode(&mut cur).unwrap();
        assert_eq!(decoded.u_correlation_id, id);
    }

    #[test]
    fn correlation_id_rejects_first_byte_zero() {
        let id = [0x00u8; 16];
        let pdu = CorrelationIdPayload { u_correlation_id: id };
        assert!(encode_vec(&pdu).is_err());
    }

    #[test]
    fn correlation_id_rejects_first_byte_f4() {
        let mut id = [0x11u8; 16];
        id[0] = 0xF4;
        let pdu = CorrelationIdPayload { u_correlation_id: id };
        assert!(encode_vec(&pdu).is_err());
    }

    #[test]
    fn correlation_id_rejects_0d_anywhere() {
        let mut id = [0x11u8; 16];
        id[7] = 0x0D;
        let pdu = CorrelationIdPayload { u_correlation_id: id };
        assert!(encode_vec(&pdu).is_err());
    }

    // ── SynDataExPayload ──

    #[test]
    fn syn_data_ex_v1_roundtrip_without_cookie() {
        let pdu = SynDataExPayload {
            u_syn_ex_flags: RDPUDP_VERSION_INFO_VALID,
            u_udp_ver: RDPUDP_PROTOCOL_VERSION_1,
            cookie_hash: None,
        };
        let bytes = encode_vec(&pdu).unwrap();
        assert_eq!(bytes.len(), SYN_DATA_EX_PAYLOAD_FIXED_SIZE);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = SynDataExPayload::decode_with_cookie(&mut cur, false).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn syn_data_ex_v3_roundtrip_with_cookie() {
        let hash = [0xABu8; 32];
        let pdu = SynDataExPayload {
            u_syn_ex_flags: RDPUDP_VERSION_INFO_VALID,
            u_udp_ver: RDPUDP_PROTOCOL_VERSION_3,
            cookie_hash: Some(hash),
        };
        let bytes = encode_vec(&pdu).unwrap();
        assert_eq!(bytes.len(), SYN_DATA_EX_PAYLOAD_WITH_COOKIE_SIZE);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = SynDataExPayload::decode_with_cookie(&mut cur, true).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn syn_data_ex_rejects_cookie_without_v3() {
        let pdu = SynDataExPayload {
            u_syn_ex_flags: RDPUDP_VERSION_INFO_VALID,
            u_udp_ver: RDPUDP_PROTOCOL_VERSION_1,
            cookie_hash: Some([0xAB; 32]),
        };
        assert!(encode_vec(&pdu).is_err());
    }

    // ── PayloadPrefix ──

    #[test]
    fn payload_prefix_roundtrip() {
        let pdu = PayloadPrefix { cb_payload_size: 15 };
        let bytes = encode_vec(&pdu).unwrap();
        assert_eq!(bytes, vec![0x0F, 0x00]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(PayloadPrefix::decode(&mut cur).unwrap(), pdu);
    }

    // ── SYN padding helper ──

    #[test]
    fn syn_padding_uses_min_mtu() {
        assert_eq!(syn_padding_size(40, 1200, 1132), 1132 - 40);
        assert_eq!(syn_padding_size(40, 1132, 1200), 1132 - 40);
    }

    #[test]
    fn syn_padding_zero_when_already_at_target() {
        assert_eq!(syn_padding_size(1132, 1132, 1132), 0);
        assert_eq!(syn_padding_size(1200, 1132, 1132), 0);
    }

    // ── Spec §2.2 FEC Packet example ──

    #[test]
    fn spec_fec_packet_example_decode() {
        // Prefix of the wire bytes listed in the spec's FEC Packet
        // diagram: header + ACK vector (1 element, +1 pad) + FEC
        // payload header. The trailing FEC payload is elided.
        let bytes: &[u8] = &[
            0xD6, 0xCF, 0x0A, 0xCB, // snSourceAck
            0x04, 0x00, // uReceiveWindowSize
            0x1C, 0x00, // uFlags = ACK | DATA | FEC
            0x01, 0x00, // uAckVectorSize = 1
            0x04, // AckVector[0] = state 00 run (4-1)=3? actually spec bytes say 0x04
            0x00, // DWORD align pad
            // FEC payload header
            0xEC, 0x47, 0x1A, 0xFD, 0xEC, 0x47, 0x1A, 0xFD, 0x10, 0x01, 0x00, 0x00,
        ];
        let mut cur = ReadCursor::new(bytes);
        let hdr = RdpUdpFecHeader::decode(&mut cur).unwrap();
        assert_eq!(hdr.sn_source_ack, 0xCB0A_CFD6);
        assert_eq!(hdr.u_receive_window_size, 4);
        assert_eq!(
            hdr.u_flags,
            RDPUDP_FLAG_ACK | RDPUDP_FLAG_DATA | RDPUDP_FLAG_FEC
        );

        let ack = AckVectorHeader::decode(&mut cur).unwrap();
        assert_eq!(ack.ack_vector.len(), 1);
        // 0x04 = state `DatagramReceived` (bits 7:6 = 00), wire run
        // field = 4 → decoded run_length = 5.
        assert_eq!(ack.ack_vector[0].state, VectorElementState::DatagramReceived);
        assert_eq!(ack.ack_vector[0].run_length, 5);

        let fec = FecPayloadHeader::decode(&mut cur).unwrap();
        assert_eq!(fec.sn_coded, 0xFD1A47EC);
        assert_eq!(fec.sn_source_start, 0xFD1A47EC);
        assert_eq!(fec.u_range, 0x10);
        assert_eq!(fec.u_fec_index, 0x01);
    }
}
