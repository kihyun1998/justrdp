//! Video decoder abstraction.
//!
//! The crate deliberately keeps H.264 out of tree: callers plug in their
//! own decoder by implementing [`VideoDecoder`]. A [`MockVideoDecoder`] is
//! provided for tests.

/// Decoder error surfaced from the [`VideoDecoder`] trait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VideoDecodeError {
    /// `pExtraData` (SPS/PPS) could not be parsed.
    InvalidExtraData,
    /// Underlying decoder failed to consume the sample.
    DecodeFailed(&'static str),
    /// Decoder has been shut down and refuses further samples.
    Shutdown,
}

/// Pluggable H.264 video decoder used by the VIDEO_DATA pipeline.
pub trait VideoDecoder: Send {
    /// Called once when a presentation is accepted. `extra_data` is the
    /// concatenation of SPS and PPS NAL units from `PresentationRequest`.
    fn initialize(
        &mut self,
        width: u32,
        height: u32,
        extra_data: &[u8],
    ) -> Result<(), VideoDecodeError>;

    /// Called for every reassembled sample.
    fn decode_sample(
        &mut self,
        sample: &[u8],
        timestamp_hns: Option<u64>,
        keyframe: bool,
    ) -> Result<(), VideoDecodeError>;

    /// Called when the presentation is stopped.
    fn shutdown(&mut self);
}

/// Counting mock used by unit and integration tests.
#[derive(Debug, Default, Clone)]
pub struct MockVideoDecoder {
    pub init_count: u32,
    pub frames: u32,
    pub last_keyframe: bool,
    pub last_timestamp: Option<u64>,
    pub last_sample_len: usize,
    pub shutdown_count: u32,
}

impl MockVideoDecoder {
    pub fn new() -> Self {
        Self::default()
    }
}

impl VideoDecoder for MockVideoDecoder {
    fn initialize(
        &mut self,
        _width: u32,
        _height: u32,
        _extra_data: &[u8],
    ) -> Result<(), VideoDecodeError> {
        self.init_count += 1;
        Ok(())
    }

    fn decode_sample(
        &mut self,
        sample: &[u8],
        timestamp_hns: Option<u64>,
        keyframe: bool,
    ) -> Result<(), VideoDecodeError> {
        self.frames += 1;
        self.last_keyframe = keyframe;
        self.last_timestamp = timestamp_hns;
        self.last_sample_len = sample.len();
        Ok(())
    }

    fn shutdown(&mut self) {
        self.shutdown_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_counts() {
        let mut m = MockVideoDecoder::new();
        m.initialize(480, 244, &[]).unwrap();
        m.decode_sample(&[1, 2, 3], Some(42), true).unwrap();
        m.shutdown();
        assert_eq!(m.init_count, 1);
        assert_eq!(m.frames, 1);
        assert!(m.last_keyframe);
        assert_eq!(m.last_timestamp, Some(42));
        assert_eq!(m.last_sample_len, 3);
        assert_eq!(m.shutdown_count, 1);
    }
}
