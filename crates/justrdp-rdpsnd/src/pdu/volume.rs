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

/// Pitch PDU (Server → Client) -- MS-RDPEA 2.2.3.6
///
/// Client MUST ignore this per spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PitchPdu {
    /// Raw pitch value (ignored by client).
    pub pitch: u32,
}

impl PitchPdu {
    /// Decode from cursor after the header has been read.
    pub fn decode_body(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let pitch = src.read_u32_le("PitchPdu::Pitch")?;
        Ok(Self { pitch })
    }
}

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
    fn pitch_decode() {
        let body = [0x00, 0x00, 0x01, 0x00]; // 1.0x pitch
        let mut cursor = ReadCursor::new(&body);
        let pitch = PitchPdu::decode_body(&mut cursor).unwrap();
        assert_eq!(pitch.pitch, 0x0001_0000);
    }
}
