#![forbid(unsafe_code)]

//! Training / Training Confirm PDU -- MS-RDPEA 2.2.3.1, 2.2.3.2

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{DecodeResult, Encode, EncodeResult};

use super::header::{SndHeader, SndMsgType, SND_HEADER_SIZE};

/// Training PDU (Server → Client) -- MS-RDPEA 2.2.3.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainingPdu {
    /// Timestamp to be echoed back.
    pub timestamp: u16,
    /// If non-zero, total PDU size; if zero, no data follows.
    pub pack_size: u16,
}

impl TrainingPdu {
    /// Decode from cursor after the header has been read.
    ///
    /// `body_size` is from the header; any data beyond the fixed 4 bytes is ignored.
    pub fn decode_body(src: &mut ReadCursor<'_>, body_size: u16) -> DecodeResult<Self> {
        if body_size < 4 {
            return Err(justrdp_core::DecodeError::invalid_value(
                "TrainingPdu",
                "body_size too small",
            ));
        }
        let timestamp = src.read_u16_le("TrainingPdu::wTimeStamp")?;
        let pack_size = src.read_u16_le("TrainingPdu::wPackSize")?;
        // Skip any trailing data (unused per spec).
        let extra = (body_size - 4) as usize;
        if extra > 0 {
            src.skip(extra, "TrainingPdu::data")?;
        }
        Ok(Self {
            timestamp,
            pack_size,
        })
    }
}

/// Training Confirm PDU (Client → Server) -- MS-RDPEA 2.2.3.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainingConfirmPdu {
    /// MUST equal the timestamp from the Training PDU.
    pub timestamp: u16,
    /// MUST equal the pack_size from the Training PDU.
    pub pack_size: u16,
}

impl TrainingConfirmPdu {
    /// Create from a received Training PDU (echo values).
    pub fn from_training(training: &TrainingPdu) -> Self {
        Self {
            timestamp: training.timestamp,
            pack_size: training.pack_size,
        }
    }
}

impl Encode for TrainingConfirmPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SndHeader::new(SndMsgType::Training, 4);
        header.encode(dst)?;
        dst.write_u16_le(self.timestamp, "TrainingConfirmPdu::wTimeStamp")?;
        dst.write_u16_le(self.pack_size, "TrainingConfirmPdu::wPackSize")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TrainingConfirmPdu"
    }

    fn size(&self) -> usize {
        SND_HEADER_SIZE + 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_core::Decode as _;

    #[test]
    fn training_confirm_from_training() {
        // Simulate server Training PDU body
        let body_bytes = [0x42, 0x00, 0x08, 0x00]; // timestamp=0x42, packSize=8
        let mut cursor = ReadCursor::new(&body_bytes);
        let training = TrainingPdu::decode_body(&mut cursor, 4).unwrap();
        assert_eq!(training.timestamp, 0x42);
        assert_eq!(training.pack_size, 8);

        // Build confirm
        let confirm = TrainingConfirmPdu::from_training(&training);
        let mut buf = alloc::vec![0u8; confirm.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        confirm.encode(&mut cursor).unwrap();

        // Verify header
        let mut cursor = ReadCursor::new(&buf);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::Training);
        assert_eq!(header.body_size, 4);

        // Verify echoed values
        let ts = cursor.read_u16_le("ts").unwrap();
        let ps = cursor.read_u16_le("ps").unwrap();
        assert_eq!(ts, 0x42);
        assert_eq!(ps, 8);
    }

    #[test]
    fn training_body_size_too_small() {
        let body_bytes = [0x42, 0x00, 0x08, 0x00];
        let mut cursor = ReadCursor::new(&body_bytes);
        assert!(TrainingPdu::decode_body(&mut cursor, 3).is_err());
    }

    #[test]
    fn training_with_extra_data() {
        // body_size=8: 4 fixed bytes + 4 extra bytes to skip
        let body_bytes = [
            0x42, 0x00, // timestamp=0x42
            0x08, 0x00, // packSize=8
            0xDE, 0xAD, 0xBE, 0xEF, // extra (skipped)
        ];
        let mut cursor = ReadCursor::new(&body_bytes);
        let training = TrainingPdu::decode_body(&mut cursor, 8).unwrap();
        assert_eq!(training.timestamp, 0x42);
        assert_eq!(training.pack_size, 8);
        // Cursor should be fully consumed after skipping extra data.
        assert_eq!(cursor.remaining(), 0);
    }
}
