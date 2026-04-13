//! Full MS-RDPEVOR client flow integration test.
//!
//! Runs the Control and Data DVC processors side-by-side against a
//! `MockVideoDecoder` plus a `MockGeometryLookup`, exercising the
//! Start → VIDEO_DATA(2 fragments) → Stop sequence end to end.

use std::sync::{Arc, Mutex};

use justrdp_core::{Encode, ReadCursor, WriteCursor};
use justrdp_dvc::DvcProcessor;
use justrdp_rdpegt::{GeometryEntry, GeometryLookup, IRect};
use justrdp_rdpevor::{
    PresentationRequest, PresentationResponse, RdpevorControlClient, RdpevorDataClient,
    VideoData, VideoDecoder, VideoSink, TSMM_VIDEO_DATA_FLAG_HAS_TIMESTAMPS,
    TSMM_VIDEO_DATA_FLAG_KEYFRAME,
};
use justrdp_core::Decode;

/// Thread-safe mock decoder so we can poke it from a `VideoSink` bridge.
#[derive(Default)]
struct SharedDecoder {
    init_count: u32,
    frames: u32,
    last_keyframe: bool,
    last_len: usize,
    shutdown_count: u32,
}

#[derive(Clone)]
struct DecoderHandle(Arc<Mutex<SharedDecoder>>);

impl DecoderHandle {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(SharedDecoder::default())))
    }
    fn snapshot(&self) -> SharedDecoder {
        let g = self.0.lock().unwrap();
        SharedDecoder {
            init_count: g.init_count,
            frames: g.frames,
            last_keyframe: g.last_keyframe,
            last_len: g.last_len,
            shutdown_count: g.shutdown_count,
        }
    }
}

impl VideoDecoder for DecoderHandle {
    fn initialize(
        &mut self,
        _w: u32,
        _h: u32,
        _extra: &[u8],
    ) -> Result<(), justrdp_rdpevor::VideoDecodeError> {
        self.0.lock().unwrap().init_count += 1;
        Ok(())
    }
    fn decode_sample(
        &mut self,
        sample: &[u8],
        _ts: Option<u64>,
        keyframe: bool,
    ) -> Result<(), justrdp_rdpevor::VideoDecodeError> {
        let mut g = self.0.lock().unwrap();
        g.frames += 1;
        g.last_keyframe = keyframe;
        g.last_len = sample.len();
        Ok(())
    }
    fn shutdown(&mut self) {
        self.0.lock().unwrap().shutdown_count += 1;
    }
}

/// Bridges the Data DVC's `VideoSink` into the decoder.
struct DecoderSink {
    decoder: DecoderHandle,
}
impl VideoSink for DecoderSink {
    fn on_sample(
        &mut self,
        _pid: u8,
        sample: Vec<u8>,
        ts: Option<u64>,
        keyframe: bool,
    ) {
        let _ = self.decoder.clone().decode_sample(&sample, ts, keyframe);
    }
}

struct MockGeometry {
    entry: GeometryEntry,
}
impl GeometryLookup for MockGeometry {
    fn lookup(&self, _mapping_id: u64) -> Option<&GeometryEntry> {
        Some(&self.entry)
    }
    fn active_mappings(&self) -> usize {
        1
    }
}

fn encode_pdu<E: Encode>(p: &E) -> Vec<u8> {
    let mut buf = vec![0u8; p.size()];
    let mut cur = WriteCursor::new(&mut buf);
    p.encode(&mut cur).unwrap();
    buf
}

#[test]
fn full_start_videodata_stop_flow() {
    // Decoder handle is shared between control (for init/shutdown) and the
    // data-channel sink (for sample dispatch).
    let decoder = DecoderHandle::new();

    let geom = MockGeometry {
        entry: GeometryEntry {
            top_level_id: 1,
            window_rect: IRect::new(0, 0, 480, 244),
            top_level_rect: IRect::new(0, 0, 480, 244),
            region_bound: IRect::new(0, 0, 480, 244),
            rects: vec![IRect::new(0, 0, 480, 244)],
        },
    };

    let mut control =
        RdpevorControlClient::new(Box::new(decoder.clone())).with_geometry(Box::new(geom));
    control.start(10).unwrap();

    let mut data = RdpevorDataClient::new(Box::new(DecoderSink { decoder: decoder.clone() }));
    data.start(20).unwrap();

    // 1. Server sends PresentationRequest Start.
    let start = PresentationRequest::start(
        3,
        480,
        244,
        480,
        244,
        0x0F3B_7AA4,
        0x8000_7ABA_0004_0222,
        vec![0u8; 37],
    );
    let out = control.process(10, &encode_pdu(&start)).unwrap();
    assert_eq!(out.len(), 1);

    // Decode the emitted response and sanity check.
    let mut cur = ReadCursor::new(&out[0].data);
    let resp = PresentationResponse::decode(&mut cur).unwrap();
    assert_eq!(resp.presentation_id, 3);
    assert_eq!(decoder.snapshot().init_count, 1);

    // Upstream coordinator mirrors the Control client's accepted Start
    // into the Data client so VIDEO_DATA is accepted for this presentation.
    data.register_presentation(3).unwrap();

    // 2. Server streams a single sample in two fragments (out of order).
    let frag2 = VideoData {
        presentation_id: 3,
        version: 1,
        flags: 0,
        reserved: 0,
        hns_timestamp: 0,
        hns_duration: 0,
        current_packet_index: 2,
        packets_in_sample: 2,
        sample_number: 1,
        sample: vec![0xCC, 0xDD, 0xEE],
    };
    let frag1 = VideoData {
        presentation_id: 3,
        version: 1,
        flags: TSMM_VIDEO_DATA_FLAG_HAS_TIMESTAMPS | TSMM_VIDEO_DATA_FLAG_KEYFRAME,
        reserved: 0,
        hns_timestamp: 0x06C6C7,
        hns_duration: 0,
        current_packet_index: 1,
        packets_in_sample: 2,
        sample_number: 1,
        sample: vec![0xAA, 0xBB],
    };
    data.process(20, &encode_pdu(&frag2)).unwrap();
    assert_eq!(decoder.snapshot().frames, 0);
    data.process(20, &encode_pdu(&frag1)).unwrap();
    let snap = decoder.snapshot();
    assert_eq!(snap.frames, 1);
    assert!(snap.last_keyframe);
    assert_eq!(snap.last_len, 5);

    // 3. Server sends Stop.
    let stop = PresentationRequest::stop(3);
    let out = control.process(10, &encode_pdu(&stop)).unwrap();
    assert!(out.is_empty());
    assert_eq!(decoder.snapshot().shutdown_count, 1);
    assert!(!control.is_active(3));
}
