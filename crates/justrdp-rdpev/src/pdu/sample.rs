//! Sample delivery and playback acknowledgement PDUs
//! (MS-RDPEV §2.2.5.3.3, §2.2.6.1, §2.2.8).
//!
//! These carry the actual encoded media payload from server to client
//! and the per-sample throttle ack from client to server. They are
//! the hot path of the protocol.
//!
//! - [`TsMmDataSample`] -- 36-byte fixed header + opaque `pData` blob.
//! - [`OnSample`] -- server PDU on the Server Data interface that
//!   wraps a `TsMmDataSample` with `(presentation_id, stream_id)`.
//! - [`PlaybackAck`] -- client PDU on the **Client Notifications**
//!   interface (`InterfaceValue=0x1`, `FunctionId=0x100`). Note that
//!   PLAYBACK_ACK does NOT carry a `PresentationId` -- per spec
//!   §2.2.6.1 the `StreamId` alone identifies the stream, and the
//!   client MUST send exactly one ack per `OnSample` it processed.
//!
//! ## DoS cap (checklist §10)
//!
//! [`MAX_SAMPLE_BYTES`] (16 MiB) bounds `TsMmDataSample.p_data`.
//! Real-world H.264 1080p I-frames at high bitrates can exceed 1 MiB;
//! 16 MiB leaves headroom for 4K I-frames while still bounding
//! decode-time allocation.

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{FunctionId, InterfaceValue, Mask};
use crate::pdu::guid::{decode_guid, encode_guid, Guid, GUID_SIZE};
use crate::pdu::header::{
    decode_request_header, encode_header, SharedMsgHeader, REQUEST_HEADER_SIZE,
};

// ── DoS cap (checklist §10) ─────────────────────────────────────────

/// Maximum bytes in a single `TsMmDataSample.p_data` payload.
///
/// `cbData` on the wire is u32 (4 GiB ceiling), but real samples are
/// typically tens of KiB for compressed video and a few KiB for
/// audio. 16 MiB is generous headroom for full 4K H.264 I-frames and
/// caps decode-time allocation at a reasonable upper bound.
pub const MAX_SAMPLE_BYTES: usize = 16 * 1024 * 1024;

/// Wire size of the fixed header portion of `TsMmDataSample`.
pub const TS_MM_DATA_SAMPLE_FIXED_SIZE: usize = 36;

// ── TsMmDataSample (§2.2.8) ─────────────────────────────────────────

/// One encoded media frame plus timing/extension metadata.
///
/// `sample_start_time` and `sample_end_time` are **signed** 64-bit
/// values in 100-ns units; `throttle_duration` is **unsigned** with
/// server-defined units (the client passes it through verbatim in the
/// matching `PlaybackAck`).
///
/// When `SampleExtensions & TSMM_SAMPLE_EXT_HAS_NO_TIMESTAMPS != 0`
/// the timestamps are invalid and the host pipeline should ignore
/// them. We do NOT validate this at the wire layer because the spec
/// permits arbitrary values; the host trait gets to decide.
///
/// `sample_flags` is reserved per spec §2.2.8 and MUST be ignored on
/// receipt. We pass it through verbatim so a strict roundtrip test
/// still works -- the host layer is responsible for not acting on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsMmDataSample {
    pub sample_start_time: i64,
    pub sample_end_time: i64,
    pub throttle_duration: u64,
    pub sample_flags: u32,
    /// `TSMM_SAMPLE_EXT_*` bitmask -- see [`crate::constants::sample_extensions`].
    pub sample_extensions: u32,
    /// Encoded media payload, bounded by [`MAX_SAMPLE_BYTES`].
    pub p_data: Vec<u8>,
}

impl TsMmDataSample {
    /// Wire size = 36 fixed + `p_data.len()`.
    pub fn wire_size(&self) -> usize {
        TS_MM_DATA_SAMPLE_FIXED_SIZE + self.p_data.len()
    }

    pub(crate) fn encode_inner(
        &self,
        dst: &mut WriteCursor<'_>,
        ctx: &'static str,
    ) -> EncodeResult<()> {
        if self.p_data.len() > MAX_SAMPLE_BYTES {
            return Err(EncodeError::invalid_value(ctx, "cbData too large"));
        }
        dst.write_u64_le(self.sample_start_time as u64, ctx)?;
        dst.write_u64_le(self.sample_end_time as u64, ctx)?;
        dst.write_u64_le(self.throttle_duration, ctx)?;
        dst.write_u32_le(self.sample_flags, ctx)?;
        dst.write_u32_le(self.sample_extensions, ctx)?;
        dst.write_u32_le(self.p_data.len() as u32, ctx)?;
        dst.write_slice(&self.p_data, ctx)?;
        Ok(())
    }

    pub(crate) fn decode_inner(
        src: &mut ReadCursor<'_>,
        ctx: &'static str,
    ) -> DecodeResult<Self> {
        let sample_start_time = src.read_u64_le(ctx)? as i64;
        let sample_end_time = src.read_u64_le(ctx)? as i64;
        let throttle_duration = src.read_u64_le(ctx)?;
        let sample_flags = src.read_u32_le(ctx)?;
        let sample_extensions = src.read_u32_le(ctx)?;
        let cb_data = src.read_u32_le(ctx)?;
        if cb_data as usize > MAX_SAMPLE_BYTES {
            return Err(DecodeError::invalid_value(ctx, "cbData too large"));
        }
        if (cb_data as usize) > src.remaining() {
            return Err(DecodeError::invalid_value(ctx, "cbData underflow"));
        }
        let p_data = src.read_slice(cb_data as usize, ctx)?.to_vec();
        Ok(Self {
            sample_start_time,
            sample_end_time,
            throttle_duration,
            sample_flags,
            sample_extensions,
            p_data,
        })
    }
}

// ── OnSample (§2.2.5.3.3) ───────────────────────────────────────────

/// Server delivers one media frame for a stream within a presentation.
///
/// The wire prefix is:
///
/// ```text
///   12B header   PROXY, FunctionId = 0x103
///   16B GUID     PresentationId
///    4B u32 LE   StreamId  (must be != 0 -- spec §2.2.5.1)
///    4B u32 LE   numSample = 36 + cbData
///   variable     TS_MM_DATA_SAMPLE
/// ```
///
/// `numSample` is enforced by the decoder to equal the inner sample's
/// wire size; mismatches are a structure-level violation and produce
/// a clean decode error rather than a silent off-by-N.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnSample {
    pub message_id: u32,
    pub presentation_id: Guid,
    pub stream_id: u32,
    pub sample: TsMmDataSample,
}

impl OnSample {
    fn payload_size(&self) -> usize {
        GUID_SIZE + 4 + 4 + self.sample.wire_size()
    }
}

impl Encode for OnSample {
    fn name(&self) -> &'static str {
        "MS-RDPEV::OnSample"
    }
    fn size(&self) -> usize {
        REQUEST_HEADER_SIZE + self.payload_size()
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::OnSample,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())?;
        dst.write_u32_le(self.stream_id, self.name())?;
        let sample_size = self.sample.wire_size();
        if sample_size > u32::MAX as usize {
            return Err(EncodeError::invalid_value(self.name(), "numSample overflow"));
        }
        dst.write_u32_le(sample_size as u32, self.name())?;
        self.sample.encode_inner(dst, self.name())
    }
}

impl<'de> Decode<'de> for OnSample {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::OnSample";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::OnSample)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        let stream_id = src.read_u32_le(CTX)?;
        let num_sample = src.read_u32_le(CTX)? as usize;
        if num_sample < TS_MM_DATA_SAMPLE_FIXED_SIZE {
            return Err(DecodeError::invalid_value(CTX, "numSample too small"));
        }
        let claimed_cb_data = num_sample - TS_MM_DATA_SAMPLE_FIXED_SIZE;
        if claimed_cb_data > MAX_SAMPLE_BYTES {
            return Err(DecodeError::invalid_value(CTX, "numSample too large"));
        }
        if num_sample > src.remaining() {
            return Err(DecodeError::invalid_value(CTX, "numSample underflow"));
        }
        let pos_before = src.pos();
        let sample = TsMmDataSample::decode_inner(src, CTX)?;
        if src.pos() - pos_before != num_sample {
            return Err(DecodeError::invalid_value(CTX, "numSample != 36 + cbData"));
        }
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
            stream_id,
            sample,
        })
    }
}

// ── PlaybackAck (§2.2.6.1) ──────────────────────────────────────────

/// Client throttle acknowledgement for a single `OnSample`.
///
/// PlaybackAck rides on the **Client Notifications** interface
/// (`InterfaceValue = 0x1`), so the on-wire `InterfaceId` is
/// `0x40000001`. There is no `PresentationId` field -- per spec
/// §2.2.6.1 the `StreamId` alone identifies the stream that produced
/// the sample being acknowledged.
///
/// The client MUST set:
///
/// - `data_duration` to the `throttle_duration` of the acked sample;
/// - `cb_data` to the `p_data.len()` of the acked sample;
///
/// and MUST send one ack per `OnSample` it processed (1:1 mapping).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaybackAck {
    pub message_id: u32,
    pub stream_id: u32,
    /// Echoed `throttle_duration` from the corresponding `TsMmDataSample`.
    pub data_duration: u64,
    /// Echoed `cbData` (as u64) from the corresponding `TsMmDataSample`.
    pub cb_data: u64,
}

impl PlaybackAck {
    pub const PAYLOAD_SIZE: usize = 4 + 8 + 8;
    pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for PlaybackAck {
    fn name(&self) -> &'static str {
        "MS-RDPEV::PlaybackAck"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ClientNotifications,
            self.message_id,
            FunctionId::PlaybackAck,
        );
        encode_header(dst, &header)?;
        dst.write_u32_le(self.stream_id, self.name())?;
        dst.write_u64_le(self.data_duration, self.name())?;
        dst.write_u64_le(self.cb_data, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for PlaybackAck {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::PlaybackAck";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ClientNotifications
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::PlaybackAck)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let stream_id = src.read_u32_le(CTX)?;
        let data_duration = src.read_u64_le(CTX)?;
        let cb_data = src.read_u64_le(CTX)?;
        Ok(Self {
            message_id: header.message_id,
            stream_id,
            data_duration,
            cb_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::sample_extensions;
    use alloc::vec;

    fn encode_to_vec<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        assert_eq!(cur.pos(), pdu.size(), "size() mismatch for {}", pdu.name());
        buf
    }

    // GUID from spec §4 §11.7: {8b844079-b70e-450f-8793-3d7ffa31d053}
    const ON_SAMPLE_GUID: Guid = Guid([
        0x79, 0x40, 0x84, 0x8b, 0x0e, 0xb7, 0x0f, 0x45, 0x87, 0x93, 0x3d, 0x7f, 0xfa, 0x31, 0xd0,
        0x53,
    ]);

    #[test]
    fn ts_mm_data_sample_inner_roundtrip() {
        let s = TsMmDataSample {
            sample_start_time: 1_000,
            sample_end_time: 2_000,
            throttle_duration: 0x51615,
            sample_flags: 0,
            sample_extensions: sample_extensions::CLEANPOINT,
            p_data: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };
        let mut buf: Vec<u8> = vec![0u8; s.wire_size()];
        let mut cur = WriteCursor::new(&mut buf);
        s.encode_inner(&mut cur, "test").unwrap();
        assert_eq!(buf.len(), 36 + 4);
        let mut r = ReadCursor::new(&buf);
        let back = TsMmDataSample::decode_inner(&mut r, "test").unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn ts_mm_data_sample_signed_timestamps_roundtrip() {
        // i64 negative timestamps must survive the wire; spec calls them
        // signed and they appear in real-world 'pre-roll' streams.
        let s = TsMmDataSample {
            sample_start_time: -1,
            sample_end_time: i64::MIN,
            throttle_duration: u64::MAX,
            sample_flags: 0,
            sample_extensions: 0,
            p_data: vec![],
        };
        let mut buf: Vec<u8> = vec![0u8; s.wire_size()];
        let mut cur = WriteCursor::new(&mut buf);
        s.encode_inner(&mut cur, "t").unwrap();
        let mut r = ReadCursor::new(&buf);
        let back = TsMmDataSample::decode_inner(&mut r, "t").unwrap();
        assert_eq!(back.sample_start_time, -1);
        assert_eq!(back.sample_end_time, i64::MIN);
        assert_eq!(back.throttle_duration, u64::MAX);
    }

    #[test]
    fn ts_mm_data_sample_zero_cb_data_is_legal() {
        // EOS / filler samples carry cbData = 0.
        let s = TsMmDataSample {
            sample_start_time: 0,
            sample_end_time: 0,
            throttle_duration: 0,
            sample_flags: 0,
            sample_extensions: 0,
            p_data: vec![],
        };
        assert_eq!(s.wire_size(), 36);
    }

    #[test]
    fn ts_mm_data_sample_encode_rejects_oversize_p_data() {
        let s = TsMmDataSample {
            sample_start_time: 0,
            sample_end_time: 0,
            throttle_duration: 0,
            sample_flags: 0,
            sample_extensions: 0,
            p_data: vec![0u8; MAX_SAMPLE_BYTES + 1],
        };
        let mut buf: Vec<u8> = vec![0u8; s.wire_size()];
        let mut cur = WriteCursor::new(&mut buf);
        assert!(s.encode_inner(&mut cur, "t").is_err());
    }

    #[test]
    fn ts_mm_data_sample_decode_rejects_oversize_cb_data() {
        let mut bytes: Vec<u8> = Vec::with_capacity(36);
        bytes.extend_from_slice(&0u64.to_le_bytes()); // start
        bytes.extend_from_slice(&0u64.to_le_bytes()); // end
        bytes.extend_from_slice(&0u64.to_le_bytes()); // throttle
        bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
        bytes.extend_from_slice(&0u32.to_le_bytes()); // extensions
        bytes.extend_from_slice(&((MAX_SAMPLE_BYTES as u32) + 1).to_le_bytes()); // cbData
        let mut r = ReadCursor::new(&bytes);
        assert!(TsMmDataSample::decode_inner(&mut r, "t").is_err());
    }

    #[test]
    fn on_sample_matches_spec_wire_vector() {
        // Spec §4 §11.7 (header bytes only -- the trailing 2018 bytes
        // of media data are placeholder, we use a short payload to
        // keep the test cheap). We assert the prefix bytes that the
        // spec example specifies.
        let sample = TsMmDataSample {
            sample_start_time: 0x37,
            sample_end_time: 0x38,
            throttle_duration: 0x51615,
            sample_flags: 0,
            sample_extensions: sample_extensions::CLEANPOINT
                | sample_extensions::DISCONTINUITY,
            p_data: vec![0u8; 2018],
        };
        let pdu = OnSample {
            message_id: 0,
            presentation_id: ON_SAMPLE_GUID,
            stream_id: 1,
            sample,
        };
        let bytes = encode_to_vec(&pdu);
        // Header (12) + GUID (16) + StreamId (4) + numSample (4)
        // + fixed sample (36) + cbData (2018) = 2090 bytes.
        assert_eq!(bytes.len(), 12 + 16 + 4 + 4 + 36 + 2018);

        // Header + dispatch fields:
        assert_eq!(
            &bytes[..12],
            &[
                0x00, 0x00, 0x00, 0x40, // PROXY
                0x00, 0x00, 0x00, 0x00, // MessageId
                0x03, 0x01, 0x00, 0x00, // FunctionId = ON_SAMPLE (0x103)
            ]
        );
        assert_eq!(&bytes[12..28], ON_SAMPLE_GUID.as_bytes());
        assert_eq!(&bytes[28..32], &[0x01, 0x00, 0x00, 0x00]); // StreamId = 1
        // numSample = 36 + 2018 = 2054 = 0x806
        assert_eq!(&bytes[32..36], &[0x06, 0x08, 0x00, 0x00]);
        // SampleStartTime LSB
        assert_eq!(&bytes[36..40], &[0x37, 0x00, 0x00, 0x00]);
        // SampleEndTime LSB at offset 36 + 8 = 44
        assert_eq!(&bytes[44..48], &[0x38, 0x00, 0x00, 0x00]);
        // ThrottleDuration LSB at offset 36 + 16 = 52, value 0x51615
        assert_eq!(&bytes[52..56], &[0x15, 0x16, 0x05, 0x00]);
        // SampleFlags @ 60, SampleExtensions @ 64, cbData @ 68
        assert_eq!(&bytes[60..64], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&bytes[64..68], &[0x03, 0x00, 0x00, 0x00]);
        assert_eq!(&bytes[68..72], &[0xe2, 0x07, 0x00, 0x00]); // 0x07e2 = 2018

        // Roundtrip
        let mut r = ReadCursor::new(&bytes);
        let decoded = OnSample::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn on_sample_zero_cb_data_round_trips() {
        let pdu = OnSample {
            message_id: 0,
            presentation_id: ON_SAMPLE_GUID,
            stream_id: 1,
            sample: TsMmDataSample {
                sample_start_time: 0,
                sample_end_time: 0,
                throttle_duration: 0,
                sample_flags: 0,
                sample_extensions: 0,
                p_data: vec![],
            },
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 12 + 16 + 4 + 4 + 36);
        let mut r = ReadCursor::new(&bytes);
        let decoded = OnSample::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn on_sample_decode_rejects_num_sample_size_mismatch() {
        let pdu = OnSample {
            message_id: 0,
            presentation_id: ON_SAMPLE_GUID,
            stream_id: 1,
            sample: TsMmDataSample {
                sample_start_time: 0,
                sample_end_time: 0,
                throttle_duration: 0,
                sample_flags: 0,
                sample_extensions: 0,
                p_data: vec![],
            },
        };
        let mut bytes = encode_to_vec(&pdu);
        // numSample lives at offset 32..36 (12 hdr + 16 guid + 4 sid).
        let claimed = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]) + 4;
        bytes[32..36].copy_from_slice(&claimed.to_le_bytes());
        let mut r = ReadCursor::new(&bytes);
        assert!(OnSample::decode(&mut r).is_err());
    }

    #[test]
    fn on_sample_decode_rejects_num_sample_too_small() {
        let mut bytes: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x03, 0x01, 0x00, 0x00, // ON_SAMPLE
        ];
        bytes.extend_from_slice(ON_SAMPLE_GUID.as_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes()); // StreamId
        bytes.extend_from_slice(&16u32.to_le_bytes()); // numSample = 16 (too small)
        bytes.extend_from_slice(&[0u8; 36]);
        let mut r = ReadCursor::new(&bytes);
        assert!(OnSample::decode(&mut r).is_err());
    }

    #[test]
    fn on_sample_decode_rejects_oversize_num_sample() {
        let mut bytes: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x03, 0x01, 0x00, 0x00, // ON_SAMPLE
        ];
        bytes.extend_from_slice(ON_SAMPLE_GUID.as_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        // numSample = MAX_SAMPLE_BYTES + 36 + 1 (one over the cap).
        let oversized = (MAX_SAMPLE_BYTES + TS_MM_DATA_SAMPLE_FIXED_SIZE + 1) as u32;
        bytes.extend_from_slice(&oversized.to_le_bytes());
        // Don't bother filling the rest; the cap check fires first.
        let mut r = ReadCursor::new(&bytes);
        assert!(OnSample::decode(&mut r).is_err());
    }

    #[test]
    fn playback_ack_full_layout() {
        // PLAYBACK_ACK rides on InterfaceValue=1, so on-wire InterfaceId
        // is 0x40000001 (PROXY mask | ClientNotifications value).
        let pdu = PlaybackAck {
            message_id: 0,
            stream_id: 1,
            data_duration: 0x51615,
            cb_data: 2018,
        };
        let bytes = encode_to_vec(&pdu);
        // 12 header + 4 stream + 8 duration + 8 cb_data = 32
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes.len(), PlaybackAck::WIRE_SIZE);
        assert_eq!(
            &bytes[..12],
            &[
                0x01, 0x00, 0x00, 0x40, // InterfaceId = PROXY | ClientNotifications
                0x00, 0x00, 0x00, 0x00, // MessageId
                0x00, 0x01, 0x00, 0x00, // FunctionId = PLAYBACK_ACK (0x100 on iface 1)
            ]
        );
        // StreamId @ 12, DataDuration @ 16, cbData @ 24
        assert_eq!(&bytes[12..16], &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(&bytes[16..20], &[0x15, 0x16, 0x05, 0x00]); // throttle low
        assert_eq!(&bytes[20..24], &[0x00, 0x00, 0x00, 0x00]); // throttle high
        assert_eq!(&bytes[24..32], &2018u64.to_le_bytes());

        let mut r = ReadCursor::new(&bytes);
        let decoded = PlaybackAck::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn playback_ack_rejects_server_data_interface() {
        // Same payload but on InterfaceValue=0 -- must be rejected
        // because PlaybackAck only lives on Client Notifications.
        let bytes = [
            0x00, 0x00, 0x00, 0x40, // PROXY | ServerData (wrong)
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x00, 0x01, 0x00, 0x00, // 0x100 on ServerData = EXCHANGE_CAPABILITIES_REQ
            0x01, 0x00, 0x00, 0x00, // garbage
            0, 0, 0, 0, 0, 0, 0, 0, // garbage
            0, 0, 0, 0, 0, 0, 0, 0, // garbage
        ];
        let mut r = ReadCursor::new(&bytes);
        assert!(PlaybackAck::decode(&mut r).is_err());
    }

    #[test]
    fn playback_ack_echoes_sample_fields() {
        // Cross-check: an ack built from a sample's fields round-trips
        // them faithfully. This is what the host dispatch layer will
        // do for every OnSample it processes.
        let sample = TsMmDataSample {
            sample_start_time: 0,
            sample_end_time: 0,
            throttle_duration: 0xDEAD_BEEF_CAFE,
            sample_flags: 0,
            sample_extensions: 0,
            p_data: vec![0u8; 1234],
        };
        let ack = PlaybackAck {
            message_id: 42,
            stream_id: 7,
            data_duration: sample.throttle_duration,
            cb_data: sample.p_data.len() as u64,
        };
        let bytes = encode_to_vec(&ack);
        let mut r = ReadCursor::new(&bytes);
        let decoded = PlaybackAck::decode(&mut r).unwrap();
        assert_eq!(decoded.data_duration, 0xDEAD_BEEF_CAFE);
        assert_eq!(decoded.cb_data, 1234);
        assert_eq!(decoded.stream_id, 7);
    }
}
