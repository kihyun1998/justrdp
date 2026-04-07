extern crate alloc;

use justrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

use super::{RdpgfxHeader, RDPGFX_CMDID_FRAMEACKNOWLEDGE, RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE};

// ── StartFrame (MS-RDPEGFX 2.2.2.11) — Server → Client ──

/// Start of a frame marker.
///
/// ```text
/// Offset  Size  Field
/// 8       4     timestamp (u32 LE) — packed UTC time
/// 12      4     frameId (u32 LE)
/// ```
///
/// Timestamp bit layout (MS-RDPEGFX 2.2.2.11):
/// - Bits [9:0]   (10 bits): milliseconds (0–999)
/// - Bits [15:10]  (6 bits): seconds (0–59)
/// - Bits [21:16]  (6 bits): minutes (0–59)
/// - Bits [27:22]  (6 bits): hours (0–23)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartFramePdu {
    pub timestamp: u32,
    pub frame_id: u32,
}

impl StartFramePdu {
    pub const BODY_SIZE: usize = 8;
    pub const WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + Self::BODY_SIZE;

    /// Pack a timestamp from components.
    pub fn pack_timestamp(hours: u32, minutes: u32, seconds: u32, milliseconds: u32) -> u32 {
        (hours << 22) | (minutes << 16) | (seconds << 10) | milliseconds
    }

    /// Unpack timestamp components: (hours, minutes, seconds, milliseconds).
    pub fn unpack_timestamp(ts: u32) -> (u32, u32, u32, u32) {
        let ms = ts & 0x3FF;
        let sec = (ts >> 10) & 0x3F;
        let min = (ts >> 16) & 0x3F;
        let hr = (ts >> 22) & 0x3F;
        (hr, min, sec, ms)
    }
}

impl<'de> Decode<'de> for StartFramePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            timestamp: src.read_u32_le("StartFrame::timestamp")?,
            frame_id: src.read_u32_le("StartFrame::frameId")?,
        })
    }
}

impl Encode for StartFramePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.timestamp, "StartFrame::timestamp")?;
        dst.write_u32_le(self.frame_id, "StartFrame::frameId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "StartFramePdu"
    }

    fn size(&self) -> usize {
        Self::BODY_SIZE
    }
}

// ── EndFrame (MS-RDPEGFX 2.2.2.12) — Server → Client ──

/// End of a frame marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndFramePdu {
    pub frame_id: u32,
}

impl EndFramePdu {
    pub const BODY_SIZE: usize = 4;
    pub const WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + Self::BODY_SIZE;
}

impl<'de> Decode<'de> for EndFramePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            frame_id: src.read_u32_le("EndFrame::frameId")?,
        })
    }
}

impl Encode for EndFramePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.frame_id, "EndFrame::frameId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "EndFramePdu"
    }

    fn size(&self) -> usize {
        Self::BODY_SIZE
    }
}

// ── FrameAcknowledge (MS-RDPEGFX 2.2.2.13) — Client → Server ──

/// Acknowledge a decoded frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameAcknowledgePdu {
    pub queue_depth: u32,
    pub frame_id: u32,
    pub total_frames_decoded: u32,
}

impl FrameAcknowledgePdu {
    pub const BODY_SIZE: usize = 12;
    pub const WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + Self::BODY_SIZE;
}

impl Encode for FrameAcknowledgePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RdpgfxHeader {
            cmd_id: RDPGFX_CMDID_FRAMEACKNOWLEDGE,
            flags: 0,
            pdu_length: Self::WIRE_SIZE as u32,
        };
        header.encode(dst)?;
        dst.write_u32_le(self.queue_depth, "FrameAck::queueDepth")?;
        dst.write_u32_le(self.frame_id, "FrameAck::frameId")?;
        dst.write_u32_le(self.total_frames_decoded, "FrameAck::totalFramesDecoded")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "FrameAcknowledgePdu"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for FrameAcknowledgePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let _header = RdpgfxHeader::decode(src)?;
        Ok(Self {
            queue_depth: src.read_u32_le("FrameAck::queueDepth")?,
            frame_id: src.read_u32_le("FrameAck::frameId")?,
            total_frames_decoded: src.read_u32_le("FrameAck::totalFramesDecoded")?,
        })
    }
}

// ── QoE FrameAcknowledge (MS-RDPEGFX 2.2.2.21) — Client → Server ──

/// Quality of Experience frame timing data.
///
/// MUST NOT be sent if negotiated version < VERSION10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QoeFrameAcknowledgePdu {
    pub frame_id: u32,
    pub timestamp: u32,
    pub time_diff_se: u16,
    pub time_diff_edr: u16,
}

impl QoeFrameAcknowledgePdu {
    pub const BODY_SIZE: usize = 12;
    pub const WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + Self::BODY_SIZE;
}

impl Encode for QoeFrameAcknowledgePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RdpgfxHeader {
            cmd_id: RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE,
            flags: 0,
            pdu_length: Self::WIRE_SIZE as u32,
        };
        header.encode(dst)?;
        dst.write_u32_le(self.frame_id, "QoeFrameAck::frameId")?;
        dst.write_u32_le(self.timestamp, "QoeFrameAck::timestamp")?;
        dst.write_u16_le(self.time_diff_se, "QoeFrameAck::timeDiffSE")?;
        dst.write_u16_le(self.time_diff_edr, "QoeFrameAck::timeDiffEDR")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "QoeFrameAcknowledgePdu"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for QoeFrameAcknowledgePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let _header = RdpgfxHeader::decode(src)?;
        Ok(Self {
            frame_id: src.read_u32_le("QoeFrameAck::frameId")?,
            timestamp: src.read_u32_le("QoeFrameAck::timestamp")?,
            time_diff_se: src.read_u16_le("QoeFrameAck::timeDiffSE")?,
            time_diff_edr: src.read_u16_le("QoeFrameAck::timeDiffEDR")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{QUEUE_DEPTH_UNAVAILABLE, SUSPEND_FRAME_ACKNOWLEDGEMENT};
    use alloc::vec;

    #[test]
    fn start_frame_roundtrip() {
        let pdu = StartFramePdu {
            timestamp: StartFramePdu::pack_timestamp(12, 30, 45, 500),
            frame_id: 1,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(StartFramePdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn timestamp_packing() {
        // hour=12, minute=30, second=45, millisecond=500
        // (12 << 22) | (30 << 16) | (45 << 10) | 500 = 0x031E_B5F4
        let ts = StartFramePdu::pack_timestamp(12, 30, 45, 500);
        assert_eq!(ts, 0x031E_B5F4);

        let (hr, min, sec, ms) = StartFramePdu::unpack_timestamp(ts);
        assert_eq!((hr, min, sec, ms), (12, 30, 45, 500));
    }

    #[test]
    fn timestamp_zero() {
        let ts = StartFramePdu::pack_timestamp(0, 0, 0, 0);
        assert_eq!(ts, 0);
        let (hr, min, sec, ms) = StartFramePdu::unpack_timestamp(ts);
        assert_eq!((hr, min, sec, ms), (0, 0, 0, 0));
    }

    #[test]
    fn end_frame_roundtrip() {
        let pdu = EndFramePdu { frame_id: 42 };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(EndFramePdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn frame_acknowledge_roundtrip() {
        let pdu = FrameAcknowledgePdu {
            queue_depth: QUEUE_DEPTH_UNAVAILABLE,
            frame_id: 10,
            total_frames_decoded: 10,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(FrameAcknowledgePdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn frame_acknowledge_suspend() {
        let pdu = FrameAcknowledgePdu {
            queue_depth: SUSPEND_FRAME_ACKNOWLEDGEMENT,
            frame_id: 5,
            total_frames_decoded: 5,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        // Verify queueDepth bytes at offset 8 (after header)
        assert_eq!(&buf[8..12], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn qoe_frame_acknowledge_roundtrip() {
        let pdu = QoeFrameAcknowledgePdu {
            frame_id: 100,
            timestamp: 50000,
            time_diff_se: 16,
            time_diff_edr: 8,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(QoeFrameAcknowledgePdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn qoe_clamped_values() {
        // timeDiffSE/EDR are clamped to 0 if > 65000ms; the PDU just stores the value
        let pdu = QoeFrameAcknowledgePdu {
            frame_id: 1,
            timestamp: 0,
            time_diff_se: 0,
            time_diff_edr: 0,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        let decoded = QoeFrameAcknowledgePdu::decode(&mut src).unwrap();
        assert_eq!(decoded.time_diff_se, 0);
        assert_eq!(decoded.time_diff_edr, 0);
    }
}
