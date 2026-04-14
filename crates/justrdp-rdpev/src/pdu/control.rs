//! Playback control PDUs (MS-RDPEV §2.2.5.3.2, §2.2.5.3.4, §2.2.5.3.5,
//! §2.2.5.4.1 – §2.2.5.4.5).
//!
//! These are the fire-and-forget server→client notifications that
//! drive the client's playback state machine: pre-roll buffering
//! hints, decoder flushes, end-of-stream signalling, and the play /
//! pause / stop / restart / rate-change quartet. None of them carry a
//! response, and the spec lists most of them as RECOMMENDED rather
//! than MUST -- a minimal client may parse and ignore them.
//!
//! All 8 PDUs use the Server Data interface (`InterfaceValue=0`) with
//! a `STREAM_ID_PROXY` mask. Three PDU shapes appear:
//!
//! 1. **GUID + StreamId (20B payload)**: `NotifyPreroll`, `OnFlush`,
//!    `OnEndOfStream`.
//! 2. **GUID only (16B payload)**: `OnPlaybackPaused`,
//!    `OnPlaybackStopped`, `OnPlaybackRestarted`.
//! 3. **GUID + extra (28B / 20B payload)**: `OnPlaybackStarted`
//!    (16B GUID + 8B u64 offset + 4B IsSeek) and `OnPlaybackRateChanged`
//!    (16B GUID + 4B **f32** NewRate -- not u32, per spec §2.2.5.4.5).
//!
//! The dispatch tuples are validated on decode, mirroring every other
//! PDU module in this crate.

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{FunctionId, InterfaceValue, Mask};
use crate::pdu::guid::{decode_guid, encode_guid, Guid, GUID_SIZE};
use crate::pdu::header::{
    decode_request_header, encode_header, SharedMsgHeader, REQUEST_HEADER_SIZE,
};

// ── Shape 1: GUID + StreamId (20B payload) ──────────────────────────

/// Generates a `(presentation_id, stream_id)` PDU with strict header
/// dispatch. Used for `NotifyPreroll`, `OnFlush`, and `OnEndOfStream`,
/// which share an identical wire format.
macro_rules! pres_stream_pdu {
    ($name:ident, $variant:ident, $debug_name:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name {
            pub message_id: u32,
            pub presentation_id: Guid,
            pub stream_id: u32,
        }

        impl $name {
            pub const PAYLOAD_SIZE: usize = GUID_SIZE + 4;
            pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
        }

        impl Encode for $name {
            fn name(&self) -> &'static str {
                $debug_name
            }
            fn size(&self) -> usize {
                Self::WIRE_SIZE
            }
            fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
                let header = SharedMsgHeader::request(
                    InterfaceValue::ServerData,
                    self.message_id,
                    FunctionId::$variant,
                );
                encode_header(dst, &header)?;
                encode_guid(dst, &self.presentation_id, self.name())?;
                dst.write_u32_le(self.stream_id, self.name())?;
                Ok(())
            }
        }

        impl<'de> Decode<'de> for $name {
            fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
                const CTX: &str = $debug_name;
                let header = decode_request_header(src)?;
                if header.interface_value != InterfaceValue::ServerData
                    || header.mask != Mask::Proxy
                    || header.function_id != Some(FunctionId::$variant)
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
    };
}

pres_stream_pdu!(NotifyPreroll, NotifyPreroll, "MS-RDPEV::NotifyPreroll");
pres_stream_pdu!(OnFlush, OnFlush, "MS-RDPEV::OnFlush");
pres_stream_pdu!(OnEndOfStream, OnEndOfStream, "MS-RDPEV::OnEndOfStream");

// ── Shape 2: GUID only (16B payload) ────────────────────────────────

macro_rules! pres_only_pdu {
    ($name:ident, $variant:ident, $debug_name:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name {
            pub message_id: u32,
            pub presentation_id: Guid,
        }

        impl $name {
            pub const PAYLOAD_SIZE: usize = GUID_SIZE;
            pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
        }

        impl Encode for $name {
            fn name(&self) -> &'static str {
                $debug_name
            }
            fn size(&self) -> usize {
                Self::WIRE_SIZE
            }
            fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
                let header = SharedMsgHeader::request(
                    InterfaceValue::ServerData,
                    self.message_id,
                    FunctionId::$variant,
                );
                encode_header(dst, &header)?;
                encode_guid(dst, &self.presentation_id, self.name())
            }
        }

        impl<'de> Decode<'de> for $name {
            fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
                const CTX: &str = $debug_name;
                let header = decode_request_header(src)?;
                if header.interface_value != InterfaceValue::ServerData
                    || header.mask != Mask::Proxy
                    || header.function_id != Some(FunctionId::$variant)
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
    };
}

pres_only_pdu!(OnPlaybackPaused, OnPlaybackPaused, "MS-RDPEV::OnPlaybackPaused");
pres_only_pdu!(OnPlaybackStopped, OnPlaybackStopped, "MS-RDPEV::OnPlaybackStopped");
pres_only_pdu!(OnPlaybackRestarted, OnPlaybackRestarted, "MS-RDPEV::OnPlaybackRestarted");

// ── OnPlaybackStarted (§2.2.5.4.1) — 28B payload ────────────────────

/// Server signals that playback has started for a presentation.
///
/// `playback_start_offset` is in 100-ns units (Windows reference clock
/// ticks). `is_seek == 1` distinguishes a seek-driven restart from a
/// fresh play.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnPlaybackStarted {
    pub message_id: u32,
    pub presentation_id: Guid,
    /// 100-ns ticks since the start of the presentation timeline.
    pub playback_start_offset: u64,
    /// 0 = normal start, 1 = playback resumed at a seek target.
    pub is_seek: u32,
}

impl OnPlaybackStarted {
    pub const PAYLOAD_SIZE: usize = GUID_SIZE + 8 + 4;
    pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for OnPlaybackStarted {
    fn name(&self) -> &'static str {
        "MS-RDPEV::OnPlaybackStarted"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::OnPlaybackStarted,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())?;
        dst.write_u64_le(self.playback_start_offset, self.name())?;
        dst.write_u32_le(self.is_seek, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for OnPlaybackStarted {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::OnPlaybackStarted";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::OnPlaybackStarted)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        let playback_start_offset = src.read_u64_le(CTX)?;
        let is_seek = src.read_u32_le(CTX)?;
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
            playback_start_offset,
            is_seek,
        })
    }
}

// ── OnPlaybackRateChanged (§2.2.5.4.5) — 20B payload ────────────────

/// Server changes the playback rate for a presentation. `new_rate` is
/// an **f32** (IEEE 754 single-precision) per spec §2.2.5.4.5 -- 1.0
/// is normal speed, 2.0 is 2x, 0.5 is half-speed, etc. We store it as
/// `f32` and serialise via `to_le_bytes()` to preserve every bit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OnPlaybackRateChanged {
    pub message_id: u32,
    pub presentation_id: Guid,
    pub new_rate: f32,
}

impl OnPlaybackRateChanged {
    pub const PAYLOAD_SIZE: usize = GUID_SIZE + 4;
    pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for OnPlaybackRateChanged {
    fn name(&self) -> &'static str {
        "MS-RDPEV::OnPlaybackRateChanged"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::OnPlaybackRateChanged,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())?;
        // Bit-for-bit round trip: f32::to_bits() preserves NaN payload.
        dst.write_u32_le(self.new_rate.to_bits(), self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for OnPlaybackRateChanged {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::OnPlaybackRateChanged";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::OnPlaybackRateChanged)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        let new_rate = f32::from_bits(src.read_u32_le(CTX)?);
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
            new_rate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn encode_to_vec<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        assert_eq!(cur.pos(), pdu.size(), "size() mismatch for {}", pdu.name());
        buf
    }

    const G: Guid = Guid([
        0x9f, 0x04, 0x86, 0xe0, 0x26, 0xd9, 0xae, 0x45, 0x8c, 0x0f, 0x3e, 0x05, 0x6a, 0xf3, 0xf7,
        0xd4,
    ]);

    // ── Shape 1: pres+stream ──────────────────────────────────────

    #[test]
    fn notify_preroll_roundtrip_and_function_id() {
        let pdu = NotifyPreroll {
            message_id: 0,
            presentation_id: G,
            stream_id: 1,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), NotifyPreroll::WIRE_SIZE);
        // FunctionId = NOTIFY_PREROLL (0x113)
        assert_eq!(&bytes[8..12], &[0x13, 0x01, 0x00, 0x00]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(NotifyPreroll::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn on_flush_roundtrip_and_function_id() {
        let pdu = OnFlush {
            message_id: 0,
            presentation_id: G,
            stream_id: 1,
        };
        let bytes = encode_to_vec(&pdu);
        // FunctionId = ON_FLUSH (0x10E)
        assert_eq!(&bytes[8..12], &[0x0e, 0x01, 0x00, 0x00]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(OnFlush::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn on_end_of_stream_roundtrip_and_function_id() {
        let pdu = OnEndOfStream {
            message_id: 0,
            presentation_id: G,
            stream_id: 1,
        };
        let bytes = encode_to_vec(&pdu);
        // FunctionId = ON_END_OF_STREAM (0x111)
        assert_eq!(&bytes[8..12], &[0x11, 0x01, 0x00, 0x00]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(OnEndOfStream::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn pres_stream_pdus_reject_wrong_function_id() {
        // NOTIFY_PREROLL bytes but decoded as OnFlush -- must be rejected.
        let pdu = NotifyPreroll {
            message_id: 0,
            presentation_id: G,
            stream_id: 1,
        };
        let bytes = encode_to_vec(&pdu);
        let mut r = ReadCursor::new(&bytes);
        assert!(OnFlush::decode(&mut r).is_err());
    }

    // ── Shape 2: pres only ────────────────────────────────────────

    #[test]
    fn on_playback_paused_roundtrip_and_function_id() {
        let pdu = OnPlaybackPaused {
            message_id: 0,
            presentation_id: G,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), OnPlaybackPaused::WIRE_SIZE);
        // FunctionId = ON_PLAYBACK_PAUSED (0x10A)
        assert_eq!(&bytes[8..12], &[0x0a, 0x01, 0x00, 0x00]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(OnPlaybackPaused::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn on_playback_stopped_roundtrip_and_function_id() {
        let pdu = OnPlaybackStopped {
            message_id: 0,
            presentation_id: G,
        };
        let bytes = encode_to_vec(&pdu);
        // FunctionId = ON_PLAYBACK_STOPPED (0x10B)
        assert_eq!(&bytes[8..12], &[0x0b, 0x01, 0x00, 0x00]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(OnPlaybackStopped::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn on_playback_restarted_roundtrip_and_function_id() {
        let pdu = OnPlaybackRestarted {
            message_id: 0,
            presentation_id: G,
        };
        let bytes = encode_to_vec(&pdu);
        // FunctionId = ON_PLAYBACK_RESTARTED (0x10C)
        assert_eq!(&bytes[8..12], &[0x0c, 0x01, 0x00, 0x00]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(OnPlaybackRestarted::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn pres_only_pdus_reject_wrong_function_id() {
        let pdu = OnPlaybackPaused {
            message_id: 0,
            presentation_id: G,
        };
        let bytes = encode_to_vec(&pdu);
        let mut r = ReadCursor::new(&bytes);
        assert!(OnPlaybackStopped::decode(&mut r).is_err());
    }

    // ── Shape 3: OnPlaybackStarted ────────────────────────────────

    #[test]
    fn on_playback_started_roundtrip_with_seek() {
        let pdu = OnPlaybackStarted {
            message_id: 0,
            presentation_id: G,
            playback_start_offset: 12_345_000_000, // 1.2345s in 100-ns units
            is_seek: 1,
        };
        let bytes = encode_to_vec(&pdu);
        // 12 hdr + 16 guid + 8 offset + 4 is_seek = 40
        assert_eq!(bytes.len(), 40);
        assert_eq!(bytes.len(), OnPlaybackStarted::WIRE_SIZE);
        // FunctionId = ON_PLAYBACK_STARTED (0x109)
        assert_eq!(&bytes[8..12], &[0x09, 0x01, 0x00, 0x00]);
        // Offset starts after GUID at offset 28
        assert_eq!(&bytes[28..36], &12_345_000_000u64.to_le_bytes());
        // IsSeek at 36..40
        assert_eq!(&bytes[36..40], &1u32.to_le_bytes());

        let mut r = ReadCursor::new(&bytes);
        assert_eq!(OnPlaybackStarted::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn on_playback_started_zero_offset_round_trips() {
        let pdu = OnPlaybackStarted {
            message_id: 0,
            presentation_id: G,
            playback_start_offset: 0,
            is_seek: 0,
        };
        let bytes = encode_to_vec(&pdu);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(OnPlaybackStarted::decode(&mut r).unwrap(), pdu);
    }

    // ── Shape 3: OnPlaybackRateChanged ────────────────────────────

    #[test]
    fn on_playback_rate_changed_normal_speed() {
        let pdu = OnPlaybackRateChanged {
            message_id: 0,
            presentation_id: G,
            new_rate: 1.0_f32,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), OnPlaybackRateChanged::WIRE_SIZE);
        // 1.0_f32 = 0x3f800000
        assert_eq!(&bytes[28..32], &0x3f800000u32.to_le_bytes());

        let mut r = ReadCursor::new(&bytes);
        let decoded = OnPlaybackRateChanged::decode(&mut r).unwrap();
        assert_eq!(decoded.new_rate, 1.0_f32);
    }

    #[test]
    fn on_playback_rate_changed_extreme_values() {
        // Half speed, 2x, and a NaN to verify bit-for-bit transport.
        for &rate in &[0.5_f32, 2.0_f32, -1.0_f32, f32::INFINITY, 1.5_f32] {
            let pdu = OnPlaybackRateChanged {
                message_id: 0,
                presentation_id: G,
                new_rate: rate,
            };
            let bytes = encode_to_vec(&pdu);
            let mut r = ReadCursor::new(&bytes);
            let decoded = OnPlaybackRateChanged::decode(&mut r).unwrap();
            assert_eq!(decoded.new_rate.to_bits(), rate.to_bits());
        }
    }

    #[test]
    fn on_playback_rate_changed_nan_round_trips_bit_for_bit() {
        // f32::NAN with a custom payload -- the decoder must not coerce
        // it to a canonical NaN.
        let nan_with_payload = f32::from_bits(0x7fc12345);
        let pdu = OnPlaybackRateChanged {
            message_id: 0,
            presentation_id: G,
            new_rate: nan_with_payload,
        };
        let bytes = encode_to_vec(&pdu);
        let mut r = ReadCursor::new(&bytes);
        let decoded = OnPlaybackRateChanged::decode(&mut r).unwrap();
        assert_eq!(decoded.new_rate.to_bits(), 0x7fc12345);
    }
}
