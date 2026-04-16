#![forbid(unsafe_code)]

//! MS-RDPEUDP2 v2 PDU structures (§2.2).
//!
//! Activated once `RDPUDP_PROTOCOL_VERSION_3` (`0x0101`) has been
//! negotiated inside a v1 [`SynDataExPayload`]. All post-handshake
//! data transfer switches entirely to this frame format; v1 data
//! structures are no longer used.
//!
//! A single RDPEUDP2 datagram begins with the 2-byte
//! [`RdpEudp2Header`] and then carries a sequence of optional
//! payloads in a canonical order (MS-RDPEUDP2 §2.2.1):
//!
//! ```text
//! Header                                 (2 bytes, always)
//! AckPayload       — if Flags.ACK
//! OverheadSize     — if Flags.OVERHEADSIZE
//! DelayAckInfo     — if Flags.DELAYACKINFO
//! AckOfAcks        — if Flags.AOA
//! DataHeader       — if Flags.DATA
//! AckVecPayload    — if Flags.ACKVEC
//! DataBody         — if Flags.DATA
//! ```
//!
//! [`RdpEudp2Packet`] composes them into a single top-level
//! encodable/decodable value and enforces the mutual-exclusion and
//! "at least one flag MUST be set" constraints required by §2.2.1.1.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeErrorKind, DecodeResult, Encode, EncodeError, EncodeResult,
    ReadCursor, WriteCursor,
};

// =============================================================================
// Header flag constants (§2.2.1.1)
// =============================================================================

pub const RDPUDP2_FLAG_ACK: u16 = 0x001;
pub const RDPUDP2_FLAG_DATA: u16 = 0x004;
pub const RDPUDP2_FLAG_ACKVEC: u16 = 0x008;
pub const RDPUDP2_FLAG_AOA: u16 = 0x010;
pub const RDPUDP2_FLAG_OVERHEADSIZE: u16 = 0x040;
pub const RDPUDP2_FLAG_DELAYACKINFO: u16 = 0x100;

/// Mask of the 12-bit `Flags` field inside the 16-bit header word.
const RDPUDP2_FLAGS_MASK: u16 = 0x0FFF;
/// Mask of the 4-bit `LogWindowSize` field.
const RDPUDP2_LOG_WINDOW_MASK: u16 = 0x000F;

/// Invalid sentinel in `SendAckTimeGapInMs` (§2.2.1.2.6 — "A value of
/// 255 is invalid and MUST NOT be used").
pub const ACKVEC_SENDACKTIMEGAP_INVALID: u8 = 0xFF;

// =============================================================================
// RdpEudp2Header — §2.2.1.1
// =============================================================================

/// 2-byte RDP-UDP2 packet header.
///
/// Encodes as one little-endian u16: `flags` occupies the upper 12
/// bits, `log_window_size` the lower 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdpEudp2Header {
    pub flags: u16,
    /// Log base-2 of the receive window in MTU multiples. 0..=15.
    pub log_window_size: u8,
}

pub const RDPEUDP2_HEADER_SIZE: usize = 2;

impl RdpEudp2Header {
    pub const fn new(flags: u16, log_window_size: u8) -> Self {
        Self {
            flags,
            log_window_size,
        }
    }

    /// Return `true` when the header is structurally valid per
    /// §2.2.1.1: at least one flag MUST be set, and `ACK` and
    /// `ACKVEC` MUST NOT both be set.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.flags == 0 {
            return Err("at least one flag MUST be set");
        }
        if self.flags & (RDPUDP2_FLAG_ACK | RDPUDP2_FLAG_ACKVEC)
            == (RDPUDP2_FLAG_ACK | RDPUDP2_FLAG_ACKVEC)
        {
            return Err("ACK and ACKVEC flags are mutually exclusive");
        }
        Ok(())
    }
}

impl Encode for RdpEudp2Header {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        self.validate()
            .map_err(|msg| EncodeError::invalid_value("RDPUDP2_HEADER", msg))?;
        if self.flags & !RDPUDP2_FLAGS_MASK != 0 {
            return Err(EncodeError::invalid_value(
                "RDPUDP2_HEADER",
                "flags field exceeds 12 bits",
            ));
        }
        if self.log_window_size as u16 & !RDPUDP2_LOG_WINDOW_MASK != 0 {
            return Err(EncodeError::invalid_value(
                "RDPUDP2_HEADER",
                "log_window_size exceeds 4 bits",
            ));
        }
        let word = (self.flags << 4) | (self.log_window_size as u16 & RDPUDP2_LOG_WINDOW_MASK);
        dst.write_u16_le(word, "RDPUDP2_HEADER")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP2_HEADER"
    }

    fn size(&self) -> usize {
        RDPEUDP2_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for RdpEudp2Header {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let word = src.read_u16_le("RDPUDP2_HEADER")?;
        let log_window_size = (word & RDPUDP2_LOG_WINDOW_MASK) as u8;
        let flags = (word >> 4) & RDPUDP2_FLAGS_MASK;
        let hdr = Self {
            flags,
            log_window_size,
        };
        hdr.validate().map_err(|_| {
            DecodeError::new(
                "RDPUDP2_HEADER",
                DecodeErrorKind::InvalidValue { field: "flags" },
            )
        })?;
        Ok(hdr)
    }
}

// =============================================================================
// AckPayload — §2.2.1.2.1
// =============================================================================

/// Acknowledgement payload. Fixed 7-byte prefix plus a variable
/// `delayAckTimeAdditions` trailer of `num_delayed_acks` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckPayload {
    /// Lower 16 bits of the acknowledged packet's sequence number.
    pub seq_num: u16,
    /// Lower 24 bits of the receive timestamp in 4µs units.
    pub received_ts: u32,
    /// Milliseconds between arrival of the acked packet and the
    /// sending of this ACK.
    pub send_ack_time_gap: u8,
    /// Log-scale for entries in `delay_ack_time_additions`. Each unit
    /// represents `1 << delay_ack_time_scale` microseconds.
    pub delay_ack_time_scale: u8,
    /// Reverse-ordered array of inter-ACK time gaps in
    /// `(1 << delay_ack_time_scale)`µs units. `len()` is the
    /// 4-bit `numDelayedAcks` field on the wire.
    pub delay_ack_time_additions: Vec<u8>,
}

pub const ACK_PAYLOAD_FIXED_SIZE: usize = 7;
/// Maximum value of the 4-bit `numDelayedAcks` field.
pub const ACK_PAYLOAD_MAX_DELAYED: usize = 15;

impl Encode for AckPayload {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.delay_ack_time_additions.len() > ACK_PAYLOAD_MAX_DELAYED {
            return Err(EncodeError::invalid_value(
                "RDPUDP2_ACK_PAYLOAD",
                "numDelayedAcks exceeds 4-bit field",
            ));
        }
        if self.received_ts & 0xFF00_0000 != 0 {
            return Err(EncodeError::invalid_value(
                "RDPUDP2_ACK_PAYLOAD",
                "receivedTS exceeds 24 bits",
            ));
        }
        if self.delay_ack_time_scale > 0x0F {
            return Err(EncodeError::invalid_value(
                "RDPUDP2_ACK_PAYLOAD",
                "delayAckTimeScale exceeds 4 bits",
            ));
        }
        dst.write_u16_le(self.seq_num, "SeqNum")?;
        // 24-bit little-endian: low byte, mid byte, high byte.
        dst.write_u8((self.received_ts & 0xFF) as u8, "receivedTS")?;
        dst.write_u8(((self.received_ts >> 8) & 0xFF) as u8, "receivedTS")?;
        dst.write_u8(((self.received_ts >> 16) & 0xFF) as u8, "receivedTS")?;
        dst.write_u8(self.send_ack_time_gap, "sendAckTimeGap")?;
        let packed = ((self.delay_ack_time_additions.len() as u8 & 0x0F) << 4)
            | (self.delay_ack_time_scale & 0x0F);
        dst.write_u8(packed, "numDelayedAcks/delayAckTimeScale")?;
        dst.write_slice(&self.delay_ack_time_additions, "delayAckTimeAdditions")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP2_ACK_PAYLOAD"
    }

    fn size(&self) -> usize {
        ACK_PAYLOAD_FIXED_SIZE + self.delay_ack_time_additions.len()
    }
}

impl<'de> Decode<'de> for AckPayload {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let seq_num = src.read_u16_le("SeqNum")?;
        let b0 = src.read_u8("receivedTS[0]")? as u32;
        let b1 = src.read_u8("receivedTS[1]")? as u32;
        let b2 = src.read_u8("receivedTS[2]")? as u32;
        let received_ts = b0 | (b1 << 8) | (b2 << 16);
        let send_ack_time_gap = src.read_u8("sendAckTimeGap")?;
        let packed = src.read_u8("numDelayedAcks/delayAckTimeScale")?;
        let num_delayed_acks = ((packed >> 4) & 0x0F) as usize;
        let delay_ack_time_scale = packed & 0x0F;
        let additions = src.read_slice(num_delayed_acks, "delayAckTimeAdditions")?;
        Ok(Self {
            seq_num,
            received_ts,
            send_ack_time_gap,
            delay_ack_time_scale,
            delay_ack_time_additions: additions.to_vec(),
        })
    }
}

// =============================================================================
// OverheadSizePayload — §2.2.1.2.2
// =============================================================================

/// 1-byte sender-overhead report. Present when
/// `RDPUDP2_FLAG_OVERHEADSIZE` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverheadSizePayload {
    pub overhead_size: u8,
}

impl Encode for OverheadSizePayload {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(self.overhead_size, "OverheadSize")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP2_OVERHEADSIZE_PAYLOAD"
    }

    fn size(&self) -> usize {
        1
    }
}

impl<'de> Decode<'de> for OverheadSizePayload {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            overhead_size: src.read_u8("OverheadSize")?,
        })
    }
}

// =============================================================================
// DelayAckInfoPayload — §2.2.1.2.3
// =============================================================================

/// Sender's advertised delayed-ACK policy. 3 bytes on the wire.
/// Present when `RDPUDP2_FLAG_DELAYACKINFO` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelayAckInfoPayload {
    pub max_delayed_acks: u8,
    pub delayed_ack_timeout_in_ms: u16,
}

pub const DELAY_ACK_INFO_SIZE: usize = 3;

impl Encode for DelayAckInfoPayload {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(self.max_delayed_acks, "MaxDelayedAcks")?;
        dst.write_u16_le(self.delayed_ack_timeout_in_ms, "DelayedAckTimeoutInMs")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP2_DELAYACKINFO_PAYLOAD"
    }

    fn size(&self) -> usize {
        DELAY_ACK_INFO_SIZE
    }
}

impl<'de> Decode<'de> for DelayAckInfoPayload {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let max_delayed_acks = src.read_u8("MaxDelayedAcks")?;
        let delayed_ack_timeout_in_ms = src.read_u16_le("DelayedAckTimeoutInMs")?;
        Ok(Self {
            max_delayed_acks,
            delayed_ack_timeout_in_ms,
        })
    }
}

// =============================================================================
// AckOfAcksPayload — §2.2.1.2.4
// =============================================================================

/// 2-byte ACK-of-ACKs payload. Present when `RDPUDP2_FLAG_AOA` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckOfAcksPayload {
    /// Lower 16 bits of the sequence number the sender is waiting to
    /// receive acknowledgement for.
    pub ack_of_acks_seq_num: u16,
}

impl Encode for AckOfAcksPayload {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.ack_of_acks_seq_num, "AckOfAcksSeqNum")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP2_ACKOFACKS_PAYLOAD"
    }

    fn size(&self) -> usize {
        2
    }
}

impl<'de> Decode<'de> for AckOfAcksPayload {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            ack_of_acks_seq_num: src.read_u16_le("AckOfAcksSeqNum")?,
        })
    }
}

// =============================================================================
// DataHeaderPayload — §2.2.1.2.5
// =============================================================================

/// 2-byte data-segment sequence number. Always paired with
/// [`DataBodyPayload`] when `RDPUDP2_FLAG_DATA` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHeaderPayload {
    pub data_seq_num: u16,
}

impl Encode for DataHeaderPayload {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.data_seq_num, "DataSeqNum")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP2_DATAHEADER_PAYLOAD"
    }

    fn size(&self) -> usize {
        2
    }
}

impl<'de> Decode<'de> for DataHeaderPayload {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            data_seq_num: src.read_u16_le("DataSeqNum")?,
        })
    }
}

// =============================================================================
// DataBodyPayload — §2.2.1.2.7
// =============================================================================

/// Channel sequence number + raw payload bytes. Always paired with
/// [`DataHeaderPayload`] when `RDPUDP2_FLAG_DATA` is set. The payload
/// length is implicit — it consumes every byte up to the end of the
/// UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataBodyPayload {
    pub channel_seq_num: u16,
    pub data: Vec<u8>,
}

impl DataBodyPayload {
    pub fn encoded_size(&self) -> usize {
        2 + self.data.len()
    }

    pub fn encode_into(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.channel_seq_num, "ChannelSeqNum")?;
        dst.write_slice(&self.data, "DataBody")?;
        Ok(())
    }
}

// =============================================================================
// AckVecPayload — §2.2.1.2.6
// =============================================================================

/// One byte of a coded ACK vector. Two encodings (§2.2.1.2.6):
///
/// - `StateMap`: MSB = 0. The low 7 bits are a bitmap of 7 sequence
///   numbers starting at `BaseSeqNum + already_processed`. Bit 0 is
///   the earliest sequence number; `1` = received, `0` = not
///   received.
/// - `RunLength`: MSB = 1. Bit 6 is the state (`1` = received, `0`
///   = not received). Bits 5..0 are the run length. The run length
///   is stored as-is (not minus-one) per the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodedAckVecElement {
    StateMap(u8),
    RunLength { received: bool, length: u8 },
}

impl CodedAckVecElement {
    pub fn to_byte(self) -> u8 {
        match self {
            Self::StateMap(bits) => bits & 0x7F,
            Self::RunLength { received, length } => {
                0x80 | (if received { 0x40 } else { 0 }) | (length & 0x3F)
            }
        }
    }

    pub fn from_byte(b: u8) -> Self {
        if b & 0x80 == 0 {
            Self::StateMap(b & 0x7F)
        } else {
            Self::RunLength {
                received: (b & 0x40) != 0,
                length: b & 0x3F,
            }
        }
    }
}

/// Acknowledgement vector payload. Present when
/// `RDPUDP2_FLAG_ACKVEC` is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckVecPayload {
    pub base_seq_num: u16,
    /// Optional 24-bit timestamp + `send_ack_time_gap_in_ms`. Sent
    /// when the peer has a fresh arrival timestamp for the highest
    /// unacknowledged sequence number. A `send_ack_time_gap_in_ms`
    /// of `ACKVEC_SENDACKTIMEGAP_INVALID` is rejected on encode.
    pub timestamp: Option<AckVecTimestamp>,
    pub coded_ack_vector: Vec<CodedAckVecElement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckVecTimestamp {
    pub timestamp: u32,
    pub send_ack_time_gap_in_ms: u8,
}

/// Maximum value of the 7-bit `codedAckVecSize` field.
pub const ACKVEC_MAX_CODED_SIZE: usize = 0x7F;

impl Encode for AckVecPayload {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.coded_ack_vector.len() > ACKVEC_MAX_CODED_SIZE {
            return Err(EncodeError::invalid_value(
                "RDPUDP2_ACKVEC_PAYLOAD",
                "codedAckVecSize exceeds 7-bit field",
            ));
        }
        if let Some(ts) = &self.timestamp {
            if ts.timestamp & 0xFF00_0000 != 0 {
                return Err(EncodeError::invalid_value(
                    "RDPUDP2_ACKVEC_PAYLOAD",
                    "TimeStamp exceeds 24 bits",
                ));
            }
            if ts.send_ack_time_gap_in_ms == ACKVEC_SENDACKTIMEGAP_INVALID {
                return Err(EncodeError::invalid_value(
                    "RDPUDP2_ACKVEC_PAYLOAD",
                    "SendAckTimeGapInMs value 255 is reserved",
                ));
            }
        }
        dst.write_u16_le(self.base_seq_num, "BaseSeqNum")?;
        // 16-bit flags word: bit 15 = TimeStampPresent, bits 14..8 =
        // codedAckVecSize, bits 7..0 = reserved (zero).
        let mut flags: u16 = (self.coded_ack_vector.len() as u16 & 0x7F) << 8;
        if self.timestamp.is_some() {
            flags |= 0x8000;
        }
        dst.write_u16_le(flags, "AckVecFlags")?;
        if let Some(ts) = &self.timestamp {
            dst.write_u8((ts.timestamp & 0xFF) as u8, "TimeStamp")?;
            dst.write_u8(((ts.timestamp >> 8) & 0xFF) as u8, "TimeStamp")?;
            dst.write_u8(((ts.timestamp >> 16) & 0xFF) as u8, "TimeStamp")?;
            dst.write_u8(ts.send_ack_time_gap_in_ms, "SendAckTimeGapInMs")?;
        }
        for el in &self.coded_ack_vector {
            dst.write_u8(el.to_byte(), "codedAckVector")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP2_ACKVEC_PAYLOAD"
    }

    fn size(&self) -> usize {
        let mut n = 4; // base_seq_num + flags word
        if self.timestamp.is_some() {
            n += 4; // 3 bytes timestamp + 1 byte gap
        }
        n + self.coded_ack_vector.len()
    }
}

impl<'de> Decode<'de> for AckVecPayload {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let base_seq_num = src.read_u16_le("BaseSeqNum")?;
        let flags = src.read_u16_le("AckVecFlags")?;
        let coded_size = ((flags >> 8) & 0x7F) as usize;
        let ts_present = (flags & 0x8000) != 0;
        let timestamp = if ts_present {
            let b0 = src.read_u8("TimeStamp[0]")? as u32;
            let b1 = src.read_u8("TimeStamp[1]")? as u32;
            let b2 = src.read_u8("TimeStamp[2]")? as u32;
            let send_ack_time_gap_in_ms = src.read_u8("SendAckTimeGapInMs")?;
            Some(AckVecTimestamp {
                timestamp: b0 | (b1 << 8) | (b2 << 16),
                send_ack_time_gap_in_ms,
            })
        } else {
            None
        };
        let raw = src.read_slice(coded_size, "codedAckVector")?;
        let coded_ack_vector = raw.iter().map(|b| CodedAckVecElement::from_byte(*b)).collect();
        Ok(Self {
            base_seq_num,
            timestamp,
            coded_ack_vector,
        })
    }
}

// =============================================================================
// RdpEudp2Packet — top-level composite
// =============================================================================

/// A full RDP-UDP2 datagram.
///
/// `encode` writes the header followed by every present payload in
/// the canonical wire order defined by §2.2.1. `decode` mirrors it:
/// the presence of each optional payload is taken straight from the
/// header flags, and the variable-length `DataBody` consumes every
/// byte remaining in the cursor (because its length is implicit on
/// the wire — the entire UDP datagram length is the only length
/// signal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpEudp2Packet {
    pub log_window_size: u8,
    pub ack: Option<AckPayload>,
    pub overhead_size: Option<OverheadSizePayload>,
    pub delay_ack_info: Option<DelayAckInfoPayload>,
    pub ack_of_acks: Option<AckOfAcksPayload>,
    pub data: Option<DataSegment>,
    pub ack_vec: Option<AckVecPayload>,
}

/// Paired `DataHeader` + `DataBody` payload. They always appear
/// together and are gated by the single `DATA` flag (§2.2.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSegment {
    pub header: DataHeaderPayload,
    pub body: DataBodyPayload,
}

impl RdpEudp2Packet {
    /// Build the 12-bit `flags` word from the current set of present
    /// payloads, without validation.
    pub fn flags(&self) -> u16 {
        let mut f = 0u16;
        if self.ack.is_some() {
            f |= RDPUDP2_FLAG_ACK;
        }
        if self.overhead_size.is_some() {
            f |= RDPUDP2_FLAG_OVERHEADSIZE;
        }
        if self.delay_ack_info.is_some() {
            f |= RDPUDP2_FLAG_DELAYACKINFO;
        }
        if self.ack_of_acks.is_some() {
            f |= RDPUDP2_FLAG_AOA;
        }
        if self.data.is_some() {
            f |= RDPUDP2_FLAG_DATA;
        }
        if self.ack_vec.is_some() {
            f |= RDPUDP2_FLAG_ACKVEC;
        }
        f
    }

    pub fn header(&self) -> RdpEudp2Header {
        RdpEudp2Header::new(self.flags(), self.log_window_size)
    }
}

impl Encode for RdpEudp2Packet {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = self.header();
        header.encode(dst)?;
        if let Some(p) = &self.ack {
            p.encode(dst)?;
        }
        if let Some(p) = &self.overhead_size {
            p.encode(dst)?;
        }
        if let Some(p) = &self.delay_ack_info {
            p.encode(dst)?;
        }
        if let Some(p) = &self.ack_of_acks {
            p.encode(dst)?;
        }
        if let Some(d) = &self.data {
            d.header.encode(dst)?;
        }
        if let Some(p) = &self.ack_vec {
            p.encode(dst)?;
        }
        if let Some(d) = &self.data {
            d.body.encode_into(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPUDP2_PACKET"
    }

    fn size(&self) -> usize {
        let mut n = RDPEUDP2_HEADER_SIZE;
        if let Some(p) = &self.ack {
            n += p.size();
        }
        if self.overhead_size.is_some() {
            n += 1;
        }
        if self.delay_ack_info.is_some() {
            n += DELAY_ACK_INFO_SIZE;
        }
        if self.ack_of_acks.is_some() {
            n += 2;
        }
        if let Some(d) = &self.data {
            n += 2 + d.body.encoded_size();
        }
        if let Some(p) = &self.ack_vec {
            n += p.size();
        }
        n
    }
}

impl<'de> Decode<'de> for RdpEudp2Packet {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = RdpEudp2Header::decode(src)?;
        let flags = header.flags;

        let ack = if flags & RDPUDP2_FLAG_ACK != 0 {
            Some(AckPayload::decode(src)?)
        } else {
            None
        };
        let overhead_size = if flags & RDPUDP2_FLAG_OVERHEADSIZE != 0 {
            Some(OverheadSizePayload::decode(src)?)
        } else {
            None
        };
        let delay_ack_info = if flags & RDPUDP2_FLAG_DELAYACKINFO != 0 {
            Some(DelayAckInfoPayload::decode(src)?)
        } else {
            None
        };
        let ack_of_acks = if flags & RDPUDP2_FLAG_AOA != 0 {
            Some(AckOfAcksPayload::decode(src)?)
        } else {
            None
        };

        // DataHeader (if DATA), ACKVEC (if ACKVEC), then DataBody
        // (if DATA). DataBody consumes the remainder of the cursor
        // because its length is implicit in the UDP datagram.
        let data_header = if flags & RDPUDP2_FLAG_DATA != 0 {
            Some(DataHeaderPayload::decode(src)?)
        } else {
            None
        };
        let ack_vec = if flags & RDPUDP2_FLAG_ACKVEC != 0 {
            Some(AckVecPayload::decode(src)?)
        } else {
            None
        };
        let data = if let Some(header) = data_header {
            let channel_seq_num = src.read_u16_le("ChannelSeqNum")?;
            let remaining = src.remaining();
            let data_bytes = src.read_slice(remaining, "DataBody")?;
            Some(DataSegment {
                header,
                body: DataBodyPayload {
                    channel_seq_num,
                    data: data_bytes.to_vec(),
                },
            })
        } else {
            None
        };

        Ok(Self {
            log_window_size: header.log_window_size,
            ack,
            overhead_size,
            delay_ack_info,
            ack_of_acks,
            data,
            ack_vec,
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use justrdp_core::{encode_vec, ReadCursor};

    // ── Header ──

    #[test]
    fn header_roundtrip_bit_packing() {
        // ACK flag (0x001) + log_window_size = 5 → u16 LE value
        // = (0x001 << 4) | 0x005 = 0x0015 → bytes [0x15, 0x00].
        let hdr = RdpEudp2Header::new(RDPUDP2_FLAG_ACK, 5);
        let bytes = encode_vec(&hdr).unwrap();
        assert_eq!(bytes, vec![0x15, 0x00]);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = RdpEudp2Header::decode(&mut cur).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn header_all_flags_set_packs_correctly() {
        // All six defined flags minus the mutual-exclusive pair
        // (ACK | ACKVEC) — use ACK only here.
        let flags = RDPUDP2_FLAG_ACK
            | RDPUDP2_FLAG_DATA
            | RDPUDP2_FLAG_AOA
            | RDPUDP2_FLAG_OVERHEADSIZE
            | RDPUDP2_FLAG_DELAYACKINFO;
        let hdr = RdpEudp2Header::new(flags, 0xF);
        let bytes = encode_vec(&hdr).unwrap();
        let mut cur = ReadCursor::new(&bytes);
        let decoded = RdpEudp2Header::decode(&mut cur).unwrap();
        assert_eq!(decoded.flags, flags);
        assert_eq!(decoded.log_window_size, 0xF);
    }

    #[test]
    fn header_rejects_empty_flags() {
        let hdr = RdpEudp2Header::new(0, 3);
        assert!(encode_vec(&hdr).is_err());
    }

    #[test]
    fn header_rejects_ack_and_ackvec_together() {
        let hdr = RdpEudp2Header::new(RDPUDP2_FLAG_ACK | RDPUDP2_FLAG_ACKVEC, 0);
        assert!(encode_vec(&hdr).is_err());
    }

    #[test]
    fn header_decode_rejects_ack_and_ackvec_on_wire() {
        // Pack flags = ACK | ACKVEC (= 0x009), log = 0 → word = 0x90.
        let bytes = [0x90u8, 0x00];
        let mut cur = ReadCursor::new(&bytes[..]);
        assert!(RdpEudp2Header::decode(&mut cur).is_err());
    }

    #[test]
    fn header_rejects_log_window_overflow() {
        let hdr = RdpEudp2Header::new(RDPUDP2_FLAG_ACK, 0x10);
        assert!(encode_vec(&hdr).is_err());
    }

    // ── AckPayload ──

    #[test]
    fn ack_payload_roundtrip_no_delayed() {
        let pdu = AckPayload {
            seq_num: 0x1234,
            received_ts: 0x00AA_BBCC,
            send_ack_time_gap: 0x7F,
            delay_ack_time_scale: 3,
            delay_ack_time_additions: vec![],
        };
        let bytes = encode_vec(&pdu).unwrap();
        assert_eq!(bytes.len(), ACK_PAYLOAD_FIXED_SIZE);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = AckPayload::decode(&mut cur).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn ack_payload_roundtrip_with_delayed() {
        let pdu = AckPayload {
            seq_num: 42,
            received_ts: 1_000_000,
            send_ack_time_gap: 5,
            delay_ack_time_scale: 2,
            delay_ack_time_additions: vec![1, 2, 3, 4, 5],
        };
        let bytes = encode_vec(&pdu).unwrap();
        assert_eq!(bytes.len(), ACK_PAYLOAD_FIXED_SIZE + 5);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = AckPayload::decode(&mut cur).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn ack_payload_rejects_oversized_delayed() {
        let pdu = AckPayload {
            seq_num: 0,
            received_ts: 0,
            send_ack_time_gap: 0,
            delay_ack_time_scale: 0,
            delay_ack_time_additions: vec![0; 16],
        };
        assert!(encode_vec(&pdu).is_err());
    }

    #[test]
    fn ack_payload_rejects_ts_over_24_bits() {
        let pdu = AckPayload {
            seq_num: 0,
            received_ts: 0x0100_0000,
            send_ack_time_gap: 0,
            delay_ack_time_scale: 0,
            delay_ack_time_additions: vec![],
        };
        assert!(encode_vec(&pdu).is_err());
    }

    // ── OverheadSize / DelayAckInfo / AckOfAcks / DataHeader ──

    #[test]
    fn small_fixed_payloads_roundtrip() {
        let os = OverheadSizePayload { overhead_size: 42 };
        let bytes = encode_vec(&os).unwrap();
        assert_eq!(bytes, vec![42]);
        assert_eq!(
            OverheadSizePayload::decode(&mut ReadCursor::new(&bytes)).unwrap(),
            os
        );

        let dai = DelayAckInfoPayload {
            max_delayed_acks: 4,
            delayed_ack_timeout_in_ms: 200,
        };
        let bytes = encode_vec(&dai).unwrap();
        assert_eq!(bytes.len(), DELAY_ACK_INFO_SIZE);
        assert_eq!(
            DelayAckInfoPayload::decode(&mut ReadCursor::new(&bytes)).unwrap(),
            dai
        );

        let aoa = AckOfAcksPayload {
            ack_of_acks_seq_num: 0xBEEF,
        };
        let bytes = encode_vec(&aoa).unwrap();
        assert_eq!(bytes, vec![0xEF, 0xBE]);
        assert_eq!(
            AckOfAcksPayload::decode(&mut ReadCursor::new(&bytes)).unwrap(),
            aoa
        );

        let dh = DataHeaderPayload { data_seq_num: 7 };
        let bytes = encode_vec(&dh).unwrap();
        assert_eq!(bytes, vec![7, 0]);
    }

    // ── CodedAckVecElement ──

    #[test]
    fn coded_ack_vec_state_map_roundtrip() {
        // All low 7 bits round-trip because MSB = 0.
        for bits in 0u8..=0x7F {
            let el = CodedAckVecElement::StateMap(bits);
            assert_eq!(el.to_byte(), bits);
            assert_eq!(CodedAckVecElement::from_byte(bits), el);
        }
    }

    #[test]
    fn coded_ack_vec_run_length_roundtrip() {
        // received=true, length=5 → 0x80 | 0x40 | 5 = 0xC5.
        let el = CodedAckVecElement::RunLength {
            received: true,
            length: 5,
        };
        assert_eq!(el.to_byte(), 0xC5);
        assert_eq!(CodedAckVecElement::from_byte(0xC5), el);
        // received=false, length=3 → 0x80 | 3 = 0x83.
        let el = CodedAckVecElement::RunLength {
            received: false,
            length: 3,
        };
        assert_eq!(el.to_byte(), 0x83);
        assert_eq!(CodedAckVecElement::from_byte(0x83), el);
    }

    // ── AckVecPayload ──

    #[test]
    fn ack_vec_payload_without_timestamp_roundtrip() {
        let pdu = AckVecPayload {
            base_seq_num: 100,
            timestamp: None,
            coded_ack_vector: vec![
                CodedAckVecElement::StateMap(0x7F),
                CodedAckVecElement::RunLength {
                    received: true,
                    length: 4,
                },
            ],
        };
        let bytes = encode_vec(&pdu).unwrap();
        assert_eq!(bytes.len(), pdu.size());
        assert_eq!(bytes.len(), 4 + 2);
        // Flags word: codedAckVecSize = 2 → bits 14..8 = 2 → (2 << 8) = 0x0200.
        assert_eq!(&bytes[0..2], &[100, 0]);
        assert_eq!(&bytes[2..4], &[0x00, 0x02]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(AckVecPayload::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn ack_vec_payload_with_timestamp_roundtrip() {
        let pdu = AckVecPayload {
            base_seq_num: 0xBEEF,
            timestamp: Some(AckVecTimestamp {
                timestamp: 0x00123456,
                send_ack_time_gap_in_ms: 10,
            }),
            coded_ack_vector: vec![CodedAckVecElement::StateMap(0x01)],
        };
        let bytes = encode_vec(&pdu).unwrap();
        assert_eq!(bytes.len(), pdu.size());
        // Flags word high byte: TimeStampPresent(bit 15) | (1 << 8) >> 8 = 0x81 big-end order? Let's just re-decode.
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(AckVecPayload::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn ack_vec_payload_rejects_oversize_vector() {
        let pdu = AckVecPayload {
            base_seq_num: 0,
            timestamp: None,
            coded_ack_vector: (0..(ACKVEC_MAX_CODED_SIZE + 1))
                .map(|_| CodedAckVecElement::StateMap(0))
                .collect(),
        };
        assert!(encode_vec(&pdu).is_err());
    }

    #[test]
    fn ack_vec_payload_rejects_invalid_send_ack_time_gap_sentinel() {
        let pdu = AckVecPayload {
            base_seq_num: 0,
            timestamp: Some(AckVecTimestamp {
                timestamp: 0,
                send_ack_time_gap_in_ms: ACKVEC_SENDACKTIMEGAP_INVALID,
            }),
            coded_ack_vector: vec![],
        };
        assert!(encode_vec(&pdu).is_err());
    }

    // ── RdpEudp2Packet ──

    #[test]
    fn packet_ack_only_roundtrip() {
        let pkt = RdpEudp2Packet {
            log_window_size: 8,
            ack: Some(AckPayload {
                seq_num: 7,
                received_ts: 0,
                send_ack_time_gap: 1,
                delay_ack_time_scale: 0,
                delay_ack_time_additions: vec![],
            }),
            overhead_size: None,
            delay_ack_info: None,
            ack_of_acks: None,
            data: None,
            ack_vec: None,
        };
        let bytes = encode_vec(&pkt).unwrap();
        assert_eq!(bytes.len(), pkt.size());
        let mut cur = ReadCursor::new(&bytes);
        let decoded = RdpEudp2Packet::decode(&mut cur).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn packet_data_body_roundtrip_consumes_remaining_bytes() {
        let pkt = RdpEudp2Packet {
            log_window_size: 2,
            ack: None,
            overhead_size: None,
            delay_ack_info: None,
            ack_of_acks: None,
            data: Some(DataSegment {
                header: DataHeaderPayload { data_seq_num: 11 },
                body: DataBodyPayload {
                    channel_seq_num: 22,
                    data: b"hello rdp-udp2".to_vec(),
                },
            }),
            ack_vec: None,
        };
        let bytes = encode_vec(&pkt).unwrap();
        let mut cur = ReadCursor::new(&bytes);
        let decoded = RdpEudp2Packet::decode(&mut cur).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn packet_canonical_payload_ordering() {
        // Multiple payloads all set; inspect the encoded layout.
        // Ordering: header, ACK, OVERHEADSIZE, DELAYACKINFO, AOA,
        // DataHeader, ACKVEC?, DataBody. In this test ACKVEC is
        // omitted (mutex with ACK).
        let pkt = RdpEudp2Packet {
            log_window_size: 1,
            ack: Some(AckPayload {
                seq_num: 0xAABB,
                received_ts: 0,
                send_ack_time_gap: 0,
                delay_ack_time_scale: 0,
                delay_ack_time_additions: vec![],
            }),
            overhead_size: Some(OverheadSizePayload { overhead_size: 44 }),
            delay_ack_info: Some(DelayAckInfoPayload {
                max_delayed_acks: 3,
                delayed_ack_timeout_in_ms: 100,
            }),
            ack_of_acks: Some(AckOfAcksPayload {
                ack_of_acks_seq_num: 0xCCDD,
            }),
            data: Some(DataSegment {
                header: DataHeaderPayload {
                    data_seq_num: 0xEEFF,
                },
                body: DataBodyPayload {
                    channel_seq_num: 0x1111,
                    data: vec![0xDE, 0xAD, 0xBE, 0xEF],
                },
            }),
            ack_vec: None,
        };
        let bytes = encode_vec(&pkt).unwrap();

        // Sanity: find seq_num (0xAABB) before overhead_size (44)
        // before delay_ack max (3) before AOA (0xCCDD) before
        // DataHeader (0xEEFF) before DataBody channel (0x1111).
        let pos_seq = bytes.windows(2).position(|w| w == [0xBB, 0xAA]).unwrap();
        let pos_overhead = bytes.iter().position(|b| *b == 44).unwrap();
        let pos_max_delayed = bytes.iter().rposition(|b| *b == 3).unwrap();
        let pos_aoa = bytes.windows(2).position(|w| w == [0xDD, 0xCC]).unwrap();
        let pos_data_hdr = bytes.windows(2).position(|w| w == [0xFF, 0xEE]).unwrap();
        let pos_chan = bytes.windows(2).position(|w| w == [0x11, 0x11]).unwrap();
        assert!(pos_seq < pos_overhead);
        assert!(pos_overhead < pos_max_delayed);
        assert!(pos_max_delayed < pos_aoa);
        assert!(pos_aoa < pos_data_hdr);
        assert!(pos_data_hdr < pos_chan);

        let mut cur = ReadCursor::new(&bytes);
        let decoded = RdpEudp2Packet::decode(&mut cur).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn packet_data_body_with_ackvec_still_reassembles() {
        // DATA + ACKVEC both present: DataHeader comes before ACKVEC
        // which comes before DataBody (§2.2.1 canonical order).
        let pkt = RdpEudp2Packet {
            log_window_size: 0,
            ack: None,
            overhead_size: None,
            delay_ack_info: None,
            ack_of_acks: None,
            data: Some(DataSegment {
                header: DataHeaderPayload { data_seq_num: 1 },
                body: DataBodyPayload {
                    channel_seq_num: 2,
                    data: b"XYZ".to_vec(),
                },
            }),
            ack_vec: Some(AckVecPayload {
                base_seq_num: 99,
                timestamp: None,
                coded_ack_vector: vec![CodedAckVecElement::StateMap(0x01)],
            }),
        };
        let bytes = encode_vec(&pkt).unwrap();
        let mut cur = ReadCursor::new(&bytes);
        let decoded = RdpEudp2Packet::decode(&mut cur).unwrap();
        assert_eq!(decoded, pkt);
    }
}
