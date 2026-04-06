#![forbid(unsafe_code)]

//! Volume / Pitch PDU -- MS-RDPEA 2.2.3.5, 2.2.3.6

use justrdp_core::ReadCursor;
use justrdp_core::DecodeResult;

/// Volume PDU (Server → Client) -- MS-RDPEA 2.2.3.5
///
/// Low word = left channel, high word = right channel.
/// 0xFFFF = full volume, 0x0000 = silence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumePdu {
    /// Raw volume value.
    pub volume: u32,
}

impl VolumePdu {
    /// Decode from cursor after the header has been read.
    pub fn decode_body(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let volume = src.read_u32_le("VolumePdu::Volume")?;
        Ok(Self { volume })
    }

    /// Left channel volume (0x0000..0xFFFF).
    pub fn left(&self) -> u16 {
        self.volume as u16
    }

    /// Right channel volume (0x0000..0xFFFF).
    pub fn right(&self) -> u16 {
        (self.volume >> 16) as u16
    }
}

// Pitch PDU (MS-RDPEA 2.2.3.6) intentionally not implemented:
// client MUST ignore pitch per spec, and the processor skips SetPitch.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_channels() {
        let body = [0xFF, 0xFF, 0x00, 0x80]; // left=0xFFFF, right=0x8000
        let mut cursor = ReadCursor::new(&body);
        let vol = VolumePdu::decode_body(&mut cursor).unwrap();
        assert_eq!(vol.left(), 0xFFFF);
        assert_eq!(vol.right(), 0x8000);
    }

    #[test]
    fn volume_silence() {
        let body = [0x00, 0x00, 0x00, 0x00]; // both channels silence
        let mut cursor = ReadCursor::new(&body);
        let vol = VolumePdu::decode_body(&mut cursor).unwrap();
        assert_eq!(vol.left(), 0x0000);
        assert_eq!(vol.right(), 0x0000);
    }

    #[test]
    fn volume_left_max_right_zero() {
        let body = [0xFF, 0xFF, 0x00, 0x00]; // left=0xFFFF, right=0x0000
        let mut cursor = ReadCursor::new(&body);
        let vol = VolumePdu::decode_body(&mut cursor).unwrap();
        assert_eq!(vol.left(), 0xFFFF);
        assert_eq!(vol.right(), 0x0000);
    }

    #[test]
    fn volume_left_zero_right_max() {
        let body = [0x00, 0x00, 0xFF, 0xFF]; // left=0x0000, right=0xFFFF
        let mut cursor = ReadCursor::new(&body);
        let vol = VolumePdu::decode_body(&mut cursor).unwrap();
        assert_eq!(vol.left(), 0x0000);
        assert_eq!(vol.right(), 0xFFFF);
    }

}
