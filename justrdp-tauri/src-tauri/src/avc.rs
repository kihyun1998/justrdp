//! Placeholder `AvcDecoder` so AVC420 / AVC444 payloads have somewhere
//! to land before the real WebCodecs backend (PRD #20 / issue #26)
//! ships. Returns `Ok(None)` for every chunk — no decoded frame, but
//! no error either, so the dispatch path stays exercised.

use justrdp_graphics::avc::{AvcDecoder, AvcError, Yuv420Frame};

pub struct NoopAvcDecoder;

impl AvcDecoder for NoopAvcDecoder {
    fn decode_frame(&mut self, _annex_b: &[u8]) -> Result<Option<Yuv420Frame>, AvcError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_decoder_returns_no_frame_for_any_input() {
        let mut d = NoopAvcDecoder;
        assert!(matches!(d.decode_frame(&[]), Ok(None)));
        assert!(matches!(d.decode_frame(&[0xCA, 0xFE]), Ok(None)));
    }
}
