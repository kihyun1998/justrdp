//! MS-RDPEVOR Data channel DVC processor.
//!
//! Reassembles fragmented `TSMM_VIDEO_DATA` samples and forwards the
//! completed byte stream to a [`VideoSink`]. Missing or out-of-order
//! fragments are tolerated: fragments are buffered in a per-presentation
//! `BTreeMap<(SampleNumber, CurrentPacketIndex), Vec<u8>>` and emitted
//! only when every index in `[1, PacketsInSample]` has been received.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, ReadCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::pdu::{
    VideoData, DATA_CHANNEL_NAME, MAX_CONCURRENT_PRESENTATIONS,
    MAX_PENDING_REASSEMBLY_SAMPLES, MAX_PER_PRESENTATION_REASSEMBLY_BYTES,
    TSMM_VIDEO_DATA_FLAG_HAS_TIMESTAMPS, TSMM_VIDEO_DATA_FLAG_KEYFRAME,
};

/// Destination for reassembled video samples.
pub trait VideoSink: Send {
    fn on_sample(
        &mut self,
        presentation_id: u8,
        sample: Vec<u8>,
        timestamp_hns: Option<u64>,
        keyframe: bool,
    );
}

// Per-sample reassembly scratchpad.
struct PendingSample {
    packets_in_sample: u16,
    fragments: BTreeMap<u16, Vec<u8>>,
    hns_timestamp: u64,
    has_timestamp: bool,
    keyframe: bool,
}

impl PendingSample {
    fn new(packets_in_sample: u16) -> Self {
        Self {
            packets_in_sample,
            fragments: BTreeMap::new(),
            hns_timestamp: 0,
            has_timestamp: false,
            keyframe: false,
        }
    }

    fn is_complete(&self) -> bool {
        self.fragments.len() as u16 == self.packets_in_sample
    }

    fn assemble(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 1..=self.packets_in_sample {
            if let Some(frag) = self.fragments.remove(&i) {
                out.extend_from_slice(&frag);
            }
        }
        out
    }

    fn total_bytes(&self) -> usize {
        self.fragments.values().map(Vec::len).sum()
    }
}

// Per-presentation reassembly state with a running byte budget.
#[derive(Default)]
struct PresentationReassembly {
    samples: BTreeMap<u32, PendingSample>,
    bytes_in_flight: usize,
}

/// Client-side processor for the Data DVC.
pub struct RdpevorDataClient {
    sink: Box<dyn VideoSink>,
    /// Per-presentation, per-SampleNumber reassembly state.
    pending: BTreeMap<u8, PresentationReassembly>,
    /// Presentation IDs that received a matching `Start` on the Control
    /// channel. VIDEO_DATA for unknown/inactive IDs is discarded per
    /// MS-RDPEVOR §3.2.5.1. The upstream coordinator is responsible for
    /// invoking [`RdpevorDataClient::register_presentation`] and
    /// [`RdpevorDataClient::unregister_presentation`] in lockstep with the
    /// Control client's state transitions.
    active: BTreeSet<u8>,
    channel_id: u32,
    open: bool,
}

impl core::fmt::Debug for RdpevorDataClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdpevorDataClient")
            .field("channel_id", &self.channel_id)
            .field("open", &self.open)
            .field("pending_presentations", &self.pending.len())
            .finish()
    }
}

impl RdpevorDataClient {
    pub fn new(sink: Box<dyn VideoSink>) -> Self {
        Self {
            sink,
            pending: BTreeMap::new(),
            active: BTreeSet::new(),
            channel_id: 0,
            open: false,
        }
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn pending_samples_for(&self, presentation_id: u8) -> usize {
        self.pending
            .get(&presentation_id)
            .map_or(0, |r| r.samples.len())
    }

    pub fn pending_bytes_for(&self, presentation_id: u8) -> usize {
        self.pending
            .get(&presentation_id)
            .map_or(0, |r| r.bytes_in_flight)
    }

    /// Mark a presentation id as active so that subsequent VIDEO_DATA is
    /// accepted. Called by the upstream coordinator after the Control
    /// channel accepted a `PresentationRequest::Start`.
    ///
    /// Fails with a protocol error if the per-channel concurrent
    /// presentation cap would be exceeded.
    pub fn register_presentation(&mut self, presentation_id: u8) -> DvcResult<()> {
        if self.active.contains(&presentation_id) {
            return Ok(());
        }
        if self.active.len() >= MAX_CONCURRENT_PRESENTATIONS {
            return Err(DvcError::Protocol(String::from(
                "RDPEVOR data: MAX_CONCURRENT_PRESENTATIONS exceeded",
            )));
        }
        self.active.insert(presentation_id);
        Ok(())
    }

    /// Remove a presentation id and drop any associated reassembly state.
    pub fn unregister_presentation(&mut self, presentation_id: u8) {
        self.active.remove(&presentation_id);
        self.pending.remove(&presentation_id);
    }

    fn ingest(&mut self, vd: VideoData) -> DvcResult<()> {
        // Discard VIDEO_DATA for unknown/inactive presentations per
        // MS-RDPEVOR §3.2.5.1 (silent drop — not a protocol error).
        if !self.active.contains(&vd.presentation_id) {
            return Ok(());
        }

        let has_timestamp = vd.flags & TSMM_VIDEO_DATA_FLAG_HAS_TIMESTAMPS != 0;
        let keyframe = vd.flags & TSMM_VIDEO_DATA_FLAG_KEYFRAME != 0;

        // Fast path: single-fragment sample → dispatch immediately.
        if vd.packets_in_sample == 1 {
            let ts = if has_timestamp { Some(vd.hns_timestamp) } else { None };
            self.sink
                .on_sample(vd.presentation_id, vd.sample, ts, keyframe);
            return Ok(());
        }

        // Multi-fragment: insert into reassembly buffer.
        let r = self.pending.entry(vd.presentation_id).or_default();

        // Enforce the count cap first: evict the oldest pending sample if
        // we would otherwise exceed it when inserting a new SampleNumber.
        if r.samples.len() >= MAX_PENDING_REASSEMBLY_SAMPLES
            && !r.samples.contains_key(&vd.sample_number)
        {
            if let Some(&oldest) = r.samples.keys().next() {
                if let Some(old) = r.samples.remove(&oldest) {
                    r.bytes_in_flight = r.bytes_in_flight.saturating_sub(old.total_bytes());
                }
            }
        }

        let entry = r
            .samples
            .entry(vd.sample_number)
            .or_insert_with(|| PendingSample::new(vd.packets_in_sample));
        if entry.packets_in_sample != vd.packets_in_sample {
            // Inconsistent fragmentation → drop the existing sample.
            // This branch only ever fires for a pre-existing slot: a
            // freshly-inserted entry from the `or_insert_with` above
            // would have `packets_in_sample == vd.packets_in_sample` by
            // construction. The subtraction therefore drains the
            // already-counted bytes of the prior fragments.
            if let Some(old) = r.samples.remove(&vd.sample_number) {
                r.bytes_in_flight = r.bytes_in_flight.saturating_sub(old.total_bytes());
            }
            return Ok(());
        }
        if has_timestamp {
            entry.hns_timestamp = vd.hns_timestamp;
            entry.has_timestamp = true;
        }
        if keyframe {
            entry.keyframe = true;
        }
        if entry.fragments.contains_key(&vd.current_packet_index) {
            // Duplicate fragment for the same slot → drop the duplicate
            // without touching the already-buffered fragment.
            return Ok(());
        }
        // Enforce the per-presentation byte budget BEFORE inserting the
        // new fragment. An attacker that repeatedly sends first fragments
        // of ever-new SampleNumbers would otherwise grow pending state
        // without bound.
        let frag_len = vd.sample.len();
        if r.bytes_in_flight.saturating_add(frag_len) > MAX_PER_PRESENTATION_REASSEMBLY_BYTES {
            // Drop this fragment and the sample it belongs to; the peer
            // will retransmit or request a keyframe on timeout.
            if let Some(old) = r.samples.remove(&vd.sample_number) {
                r.bytes_in_flight = r.bytes_in_flight.saturating_sub(old.total_bytes());
            }
            return Ok(());
        }

        // Re-fetch the entry: the byte-budget branch above may call
        // `r.samples.remove`, which invalidates any live mutable
        // reference obtained before the check.
        let entry = r
            .samples
            .get_mut(&vd.sample_number)
            .expect("sample just inserted above");
        entry.fragments.insert(vd.current_packet_index, vd.sample);
        r.bytes_in_flight += frag_len;

        let complete = r
            .samples
            .get(&vd.sample_number)
            .is_some_and(PendingSample::is_complete);
        if complete {
            let pending = r.samples.remove(&vd.sample_number).unwrap();
            r.bytes_in_flight = r.bytes_in_flight.saturating_sub(pending.total_bytes());
            let ts = if pending.has_timestamp { Some(pending.hns_timestamp) } else { None };
            // Rename to avoid shadowing the outer per-fragment `keyframe`
            // binding — this value is the OR of every fragment's flag
            // for the whole assembled sample.
            let assembled_keyframe = pending.keyframe;
            let bytes = pending.assemble();
            self.sink
                .on_sample(vd.presentation_id, bytes, ts, assembled_keyframe);
        }
        Ok(())
    }
}

impl AsAny for RdpevorDataClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl DvcProcessor for RdpevorDataClient {
    fn channel_name(&self) -> &str {
        DATA_CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        // DRDYNVC may re-create this channel; drop any state that belonged
        // to a previous lifetime so the new channel starts clean. In
        // particular, stale entries in `active` would otherwise let
        // previously-registered presentation ids bypass the gating check
        // on the re-opened channel.
        self.pending.clear();
        self.active.clear();
        self.channel_id = channel_id;
        self.open = true;
        Ok(Vec::new())
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if !self.open {
            return Err(DvcError::Protocol(String::from(
                "RDPEVOR data process() before start()",
            )));
        }
        if channel_id != self.channel_id {
            return Err(DvcError::Protocol(String::from(
                "RDPEVOR data: channel_id mismatch",
            )));
        }
        let mut cur = ReadCursor::new(payload);
        let vd = VideoData::decode(&mut cur).map_err(DvcError::Decode)?;
        if cur.remaining() != 0 {
            return Err(DvcError::Protocol(String::from(
                "RDPEVOR data: trailing bytes",
            )));
        }
        self.ingest(vd)?;
        Ok(Vec::new())
    }

    fn close(&mut self, channel_id: u32) {
        // Ignore close calls for a foreign channel or when the client is
        // already closed. Matches the `process()` channel-id contract.
        if !self.open || channel_id != self.channel_id {
            return;
        }
        self.pending.clear();
        self.active.clear();
        self.channel_id = 0;
        self.open = false;
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{encode_to_vec, TSMM_VIDEO_DATA_FLAG_HAS_TIMESTAMPS};
    use alloc::sync::Arc;
    use alloc::vec;

    /// Test sink that records samples into a shared Mutex-guarded Vec.
    /// We use `std::sync::Mutex` so the sink is `Send` without `unsafe`.
    type SampleLog = std::sync::Mutex<Vec<(u8, Vec<u8>, Option<u64>, bool)>>;

    struct RecordingSink {
        samples: Arc<SampleLog>,
    }

    impl VideoSink for RecordingSink {
        fn on_sample(
            &mut self,
            presentation_id: u8,
            sample: Vec<u8>,
            timestamp_hns: Option<u64>,
            keyframe: bool,
        ) {
            self.samples
                .lock()
                .unwrap()
                .push((presentation_id, sample, timestamp_hns, keyframe));
        }
    }

    // Compile-time assertion that `RdpevorDataClient` stays `Send`; a
    // regression (e.g. adding a non-`Send` field) will fail to compile
    // here instead of at the `DvcProcessor` registration site.
    const _: fn() = || {
        fn assert_send<T: Send>() {}
        assert_send::<RdpevorDataClient>();
    };

    fn setup() -> (RdpevorDataClient, Arc<SampleLog>) {
        let samples: Arc<SampleLog> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = RecordingSink { samples: samples.clone() };
        let mut c = RdpevorDataClient::new(Box::new(sink));
        c.start(20).unwrap();
        // All tests operate on presentation id 3.
        c.register_presentation(3).unwrap();
        (c, samples)
    }

    fn make_vd(
        pid: u8,
        flags: u8,
        sample_number: u32,
        current: u16,
        total: u16,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let vd = VideoData {
            presentation_id: pid,
            version: 1,
            flags,
            reserved: 0,
            hns_timestamp: 0x1111,
            hns_duration: 0,
            current_packet_index: current,
            packets_in_sample: total,
            sample_number,
            sample: body,
        };
        encode_to_vec(&vd).unwrap()
    }

    #[test]
    fn single_fragment_dispatched_immediately() {
        let (mut c, samples) = setup();
        let flags = TSMM_VIDEO_DATA_FLAG_HAS_TIMESTAMPS | TSMM_VIDEO_DATA_FLAG_KEYFRAME;
        let bytes = make_vd(3, flags, 1, 1, 1, vec![0xAA, 0xBB]);
        c.process(20, &bytes).unwrap();
        let recorded = samples.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let (pid, data, ts, kf) = &recorded[0];
        assert_eq!(*pid, 3);
        assert_eq!(data, &vec![0xAA, 0xBB]);
        assert_eq!(*ts, Some(0x1111));
        assert!(*kf);
    }

    #[test]
    fn multi_fragment_reassembly_out_of_order() {
        let (mut c, samples) = setup();
        // Fragment 2 first, then 1 — expect order preserved in output.
        let f2 = make_vd(3, 0, 7, 2, 2, vec![0xCC, 0xDD]);
        let f1 = make_vd(3, TSMM_VIDEO_DATA_FLAG_HAS_TIMESTAMPS, 7, 1, 2, vec![0xAA, 0xBB]);
        c.process(20, &f2).unwrap();
        assert!(samples.lock().unwrap().is_empty());
        assert_eq!(c.pending_samples_for(3), 1);
        c.process(20, &f1).unwrap();
        let recorded = samples.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let (_pid, data, ts, _kf) = &recorded[0];
        assert_eq!(data, &vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(*ts, Some(0x1111));
        assert_eq!(c.pending_samples_for(3), 0);
    }

    #[test]
    fn missing_fragment_keeps_pending() {
        let (mut c, samples) = setup();
        let f1 = make_vd(3, 0, 9, 1, 3, vec![0xAA]);
        c.process(20, &f1).unwrap();
        assert!(samples.lock().unwrap().is_empty());
        assert_eq!(c.pending_samples_for(3), 1);
    }

    #[test]
    fn unregister_presentation_drops_pending() {
        let (mut c, _) = setup();
        let f1 = make_vd(3, 0, 9, 1, 3, vec![0xAA]);
        c.process(20, &f1).unwrap();
        assert_eq!(c.pending_samples_for(3), 1);
        c.unregister_presentation(3);
        assert_eq!(c.pending_samples_for(3), 0);
    }

    #[test]
    fn reassembly_cap_evicts_oldest() {
        let (mut c, _) = setup();
        c.register_presentation(1).unwrap();
        // Fill the per-presentation cap with MAX_PENDING_REASSEMBLY_SAMPLES
        // first-fragments of distinct SampleNumbers.
        for n in 1..=MAX_PENDING_REASSEMBLY_SAMPLES as u32 {
            let bytes = make_vd(1, 0, n, 1, 2, vec![0u8]);
            c.process(20, &bytes).unwrap();
        }
        assert_eq!(c.pending_samples_for(1), MAX_PENDING_REASSEMBLY_SAMPLES);
        // One more causes eviction of the oldest.
        let bytes = make_vd(1, 0, 9999, 1, 2, vec![0u8]);
        c.process(20, &bytes).unwrap();
        assert_eq!(c.pending_samples_for(1), MAX_PENDING_REASSEMBLY_SAMPLES);
    }

    #[test]
    fn close_clears_state() {
        let (mut c, _) = setup();
        c.register_presentation(1).unwrap();
        let bytes = make_vd(1, 0, 1, 1, 2, vec![0u8]);
        c.process(20, &bytes).unwrap();
        c.close(20);
        assert!(!c.is_open());
        assert_eq!(c.pending_samples_for(1), 0);
    }

    #[test]
    fn bytes_in_flight_zero_after_reassembly_completes() {
        let (mut c, samples) = setup();
        let f1 = make_vd(3, 0, 77, 1, 2, vec![0xAA, 0xBB, 0xCC]);
        let f2 = make_vd(3, 0, 77, 2, 2, vec![0xDD, 0xEE]);
        c.process(20, &f1).unwrap();
        assert_eq!(c.pending_bytes_for(3), 3);
        c.process(20, &f2).unwrap();
        // Sample emitted; bytes_in_flight must drop back to 0.
        assert_eq!(samples.lock().unwrap().len(), 1);
        assert_eq!(c.pending_bytes_for(3), 0);
        assert_eq!(c.pending_samples_for(3), 0);
    }

    #[test]
    fn close_on_already_closed_client_is_noop() {
        let (mut c, _) = setup();
        c.close(20);
        assert!(!c.is_open());
        // Calling close() again with any channel id must not panic and
        // must not re-open the client.
        c.close(999);
        assert!(!c.is_open());
    }

    #[test]
    fn close_then_reopen_drops_stale_active_gate() {
        let (mut c, samples) = setup();
        // pid 3 is registered in setup(); close the channel.
        c.close(20);
        // Re-open the channel.
        c.start(20).unwrap();
        // VIDEO_DATA for the previously-registered pid 3 must now be
        // silently discarded because `active` was flushed on close/start.
        let bytes = make_vd(3, 0, 1, 1, 1, vec![0xAA]);
        c.process(20, &bytes).unwrap();
        assert!(samples.lock().unwrap().is_empty());
    }

    #[test]
    fn per_presentation_byte_budget_caps_pending_state() {
        use crate::pdu::{MAX_CBSAMPLE, MAX_PER_PRESENTATION_REASSEMBLY_BYTES};
        let (mut c, samples) = setup();
        // Use max-size (1 MiB) fragments across a 40-fragment sample.
        // With the 32 MiB per-presentation budget, the sample cannot be
        // reassembled; the cap trips well before all 40 fragments fit.
        let body = vec![0u8; MAX_CBSAMPLE as usize];
        for idx in 1..=40u16 {
            let bytes = make_vd(3, 0, 100, idx, 40, body.clone());
            c.process(20, &bytes).unwrap();
        }
        // Sample never completed, sink never called.
        assert!(samples.lock().unwrap().is_empty());
        // The cap is the hard invariant: bytes_in_flight MUST NOT exceed
        // the budget at any observable point.
        assert!(c.pending_bytes_for(3) <= MAX_PER_PRESENTATION_REASSEMBLY_BYTES);
    }

    #[test]
    fn unknown_presentation_id_silently_discarded() {
        let (mut c, samples) = setup();
        // pid 99 was never registered → drop, no error, no sink call.
        let bytes = make_vd(99, 0, 1, 1, 1, vec![0xAA]);
        c.process(20, &bytes).unwrap();
        assert!(samples.lock().unwrap().is_empty());
    }

    #[test]
    fn duplicate_fragment_is_ignored() {
        let (mut c, samples) = setup();
        let f1a = make_vd(3, 0, 5, 1, 2, vec![0xAA, 0xAA]);
        let f1b = make_vd(3, 0, 5, 1, 2, vec![0xFF, 0xFF]);
        c.process(20, &f1a).unwrap();
        // Duplicate fragment for (sample=5, index=1) must not overwrite.
        c.process(20, &f1b).unwrap();
        // Now complete the sample with the second fragment.
        let f2 = make_vd(3, 0, 5, 2, 2, vec![0xBB, 0xBB]);
        c.process(20, &f2).unwrap();
        let recorded = samples.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].1, vec![0xAA, 0xAA, 0xBB, 0xBB]);
    }

    #[test]
    fn channel_id_mismatch_is_error() {
        let (mut c, _) = setup();
        let bytes = make_vd(3, 0, 1, 1, 1, vec![0xAA]);
        assert!(matches!(c.process(999, &bytes), Err(DvcError::Protocol(_))));
    }

    #[test]
    fn malformed_payload_is_decode_error() {
        let (mut c, _) = setup();
        assert!(matches!(c.process(20, &[0u8; 4]), Err(DvcError::Decode(_))));
    }
}
