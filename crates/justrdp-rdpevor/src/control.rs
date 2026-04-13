//! MS-RDPEVOR Control channel DVC processor.
//!
//! The control processor owns the [`VideoDecoder`] instance. On receiving
//! a Start [`PresentationRequest`] it validates state, consults the
//! optional [`GeometryLookup`], initializes the decoder and emits a
//! [`PresentationResponse`]. On Stop it shuts the decoder down. Duplicate
//! Start / Stop without Start are ignored silently per §3.2.5.1.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, ReadCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};
use justrdp_rdpegt::GeometryLookup;

use crate::decoder::VideoDecoder;
use crate::pdu::{
    encode_to_vec, PresentationRequest, PresentationResponse, CONTROL_CHANNEL_NAME,
    MAX_CONCURRENT_PRESENTATIONS, MF_VIDEO_FORMAT_H264_BYTES, TSMM_VIDEO_PLAYBACK_COMMAND_START,
    TSMM_VIDEO_PLAYBACK_COMMAND_STOP,
};

/// Bookkeeping for one active presentation on the control side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationEntry {
    pub source_width: u32,
    pub source_height: u32,
    pub scaled_width: u32,
    pub scaled_height: u32,
    pub geometry_mapping_id: u64,
}

/// Type-erased geometry lookup port.
pub type BoxedGeometryLookup = Box<dyn GeometryLookup + Send>;

/// Client-side processor for the Control DVC.
pub struct RdpevorControlClient {
    decoder: Box<dyn VideoDecoder>,
    geometry: Option<BoxedGeometryLookup>,
    active: BTreeMap<u8, PresentationEntry>,
    channel_id: u32,
    open: bool,
}

impl core::fmt::Debug for RdpevorControlClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdpevorControlClient")
            .field("active", &self.active)
            .field("channel_id", &self.channel_id)
            .field("open", &self.open)
            .finish()
    }
}

impl RdpevorControlClient {
    pub fn new(decoder: Box<dyn VideoDecoder>) -> Self {
        Self {
            decoder,
            geometry: None,
            active: BTreeMap::new(),
            channel_id: 0,
            open: false,
        }
    }

    pub fn with_geometry(mut self, geometry: BoxedGeometryLookup) -> Self {
        self.geometry = Some(geometry);
        self
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn is_active(&self, presentation_id: u8) -> bool {
        self.active.contains_key(&presentation_id)
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    pub fn decoder_ref(&self) -> &dyn VideoDecoder {
        &*self.decoder
    }

    /// Apply a decoded request. Returns the response (if any) that should
    /// be sent back to the server.
    fn apply(&mut self, req: PresentationRequest) -> DvcResult<Option<PresentationResponse>> {
        match req.command {
            TSMM_VIDEO_PLAYBACK_COMMAND_START => {
                // Duplicate Start → silent ignore.
                if self.active.contains_key(&req.presentation_id) {
                    return Ok(None);
                }
                // Unknown subtype → silent (no response, no state change).
                if req.video_subtype_id != MF_VIDEO_FORMAT_H264_BYTES {
                    return Ok(None);
                }
                if self.active.len() >= MAX_CONCURRENT_PRESENTATIONS {
                    return Err(DvcError::Protocol(String::from(
                        "RDPEVOR: MAX_CONCURRENT_PRESENTATIONS exceeded",
                    )));
                }
                // Optional geometry resolution; non-fatal if missing.
                if let Some(geom) = self.geometry.as_ref() {
                    let _ = geom.lookup(req.geometry_mapping_id);
                }
                self.decoder
                    .initialize(req.scaled_width, req.scaled_height, &req.extra_data)
                    .map_err(|_| {
                        DvcError::Protocol(String::from("RDPEVOR: decoder init failed"))
                    })?;
                self.active.insert(
                    req.presentation_id,
                    PresentationEntry {
                        source_width: req.source_width,
                        source_height: req.source_height,
                        scaled_width: req.scaled_width,
                        scaled_height: req.scaled_height,
                        geometry_mapping_id: req.geometry_mapping_id,
                    },
                );
                Ok(Some(PresentationResponse::new(req.presentation_id)))
            }
            TSMM_VIDEO_PLAYBACK_COMMAND_STOP => {
                if self.active.remove(&req.presentation_id).is_some() {
                    self.decoder.shutdown();
                }
                Ok(None)
            }
            // decode() already rejects other commands.
            _ => Ok(None),
        }
    }
}

impl AsAny for RdpevorControlClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl DvcProcessor for RdpevorControlClient {
    fn channel_name(&self) -> &str {
        CONTROL_CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        self.channel_id = channel_id;
        self.open = true;
        Ok(Vec::new())
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if !self.open {
            return Err(DvcError::Protocol(String::from(
                "RDPEVOR control process() before start()",
            )));
        }
        if channel_id != self.channel_id {
            return Err(DvcError::Protocol(String::from(
                "RDPEVOR control: channel_id mismatch",
            )));
        }
        let mut cur = ReadCursor::new(payload);
        let req = PresentationRequest::decode(&mut cur).map_err(DvcError::Decode)?;
        if cur.remaining() != 0 {
            return Err(DvcError::Protocol(String::from(
                "RDPEVOR control: trailing bytes",
            )));
        }
        match self.apply(req)? {
            Some(resp) => {
                let bytes = encode_to_vec(&resp).map_err(DvcError::Encode)?;
                Ok(alloc::vec![DvcMessage::new(bytes)])
            }
            None => Ok(Vec::new()),
        }
    }

    fn close(&mut self, _channel_id: u32) {
        // A single decoder instance is shared across all presentations; the
        // trait contract treats `shutdown` as idempotent and per-channel,
        // so call it exactly once on channel close regardless of how many
        // presentations were still active.
        if !self.active.is_empty() {
            self.decoder.shutdown();
        }
        self.active.clear();
        self.open = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::MockVideoDecoder;
    use alloc::vec;

    fn encode_req(req: &PresentationRequest) -> Vec<u8> {
        encode_to_vec(req).unwrap()
    }

    fn new_client() -> RdpevorControlClient {
        let mut c = RdpevorControlClient::new(Box::new(MockVideoDecoder::new()));
        c.start(10).unwrap();
        c
    }

    fn start_req(pid: u8) -> PresentationRequest {
        PresentationRequest::start(pid, 480, 244, 480, 244, 0, 0, vec![0xAA; 4])
    }

    #[test]
    fn start_returns_response() {
        let mut c = new_client();
        let bytes = encode_req(&start_req(1));
        let out = c.process(10, &bytes).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].data.len(), 12);
        // response cbSize=12, type=2, PresentationId=1
        assert_eq!(&out[0].data[0..4], &12u32.to_le_bytes());
        assert_eq!(&out[0].data[4..8], &2u32.to_le_bytes());
        assert_eq!(out[0].data[8], 1);
        assert!(c.is_active(1));
        assert_eq!(c.active_count(), 1);
    }

    #[test]
    fn duplicate_start_ignored() {
        let mut c = new_client();
        let bytes = encode_req(&start_req(1));
        c.process(10, &bytes).unwrap();
        let out = c.process(10, &bytes).unwrap();
        assert!(out.is_empty()); // ignored
        assert_eq!(c.active_count(), 1);
    }

    #[test]
    fn stop_tears_down() {
        let mut c = new_client();
        c.process(10, &encode_req(&start_req(1))).unwrap();
        let stop = encode_req(&PresentationRequest::stop(1));
        let out = c.process(10, &stop).unwrap();
        assert!(out.is_empty());
        assert!(!c.is_active(1));
    }

    #[test]
    fn stop_without_start_is_silent() {
        let mut c = new_client();
        let stop = encode_req(&PresentationRequest::stop(5));
        let out = c.process(10, &stop).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn unknown_subtype_ignored() {
        let mut c = new_client();
        let mut req = start_req(1);
        req.video_subtype_id = [0xFF; 16];
        let bytes = encode_req(&req);
        let out = c.process(10, &bytes).unwrap();
        assert!(out.is_empty());
        assert!(!c.is_active(1));
    }

    #[test]
    fn malformed_payload_is_decode_error() {
        let mut c = new_client();
        let err = c.process(10, &[0u8; 6]);
        assert!(matches!(err, Err(DvcError::Decode(_))));
    }

    #[test]
    fn close_clears_state() {
        let mut c = new_client();
        c.process(10, &encode_req(&start_req(1))).unwrap();
        c.close(10);
        assert!(!c.is_open());
        assert_eq!(c.active_count(), 0);
    }

    #[test]
    fn process_before_start_errors() {
        let mut c = RdpevorControlClient::new(Box::new(MockVideoDecoder::new()));
        let err = c.process(10, &encode_req(&start_req(1)));
        assert!(err.is_err());
    }
}
