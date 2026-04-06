#![forbid(unsafe_code)]

//! Fast-Path fragment reassembly -- MS-RDPBCGR 2.2.9.1.2.1
//!
//! Updates can be fragmented across multiple `FastPathOutputUpdate` PDUs.
//! This module reassembles them into complete logical updates.

use alloc::vec::Vec;

use justrdp_pdu::rdp::fast_path::{FastPathOutputUpdate, FastPathUpdateType, Fragmentation};

/// Maximum reassembly buffer size (16 MiB).
/// Prevents unbounded heap growth from malicious fragment streams.
const MAX_REASSEMBLY_BYTES: usize = 16 * 1024 * 1024;

/// Reassembly buffer for fragmented fast-path updates.
#[derive(Debug)]
pub(crate) struct CompleteData {
    /// Accumulated fragment data.
    buffer: Vec<u8>,
    /// The update code from the FIRST fragment (determines the type of the assembled update).
    update_code: Option<FastPathUpdateType>,
}

/// A reassembled (or single) update ready for dispatch.
#[derive(Debug)]
pub(crate) struct AssembledUpdate {
    pub update_code: FastPathUpdateType,
    pub data: Vec<u8>,
}

impl Default for CompleteData {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            update_code: None,
        }
    }
}

impl CompleteData {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a single `FastPathOutputUpdate` fragment.
    ///
    /// Returns `Some(AssembledUpdate)` when a complete update is ready (either
    /// a `Single` fragment or a `Last` fragment completing reassembly).
    /// Returns `None` when more fragments are needed.
    pub fn process_update(&mut self, update: &FastPathOutputUpdate) -> Option<AssembledUpdate> {
        match update.fragmentation {
            Fragmentation::Single => {
                // No reassembly needed; dispatch directly.
                self.reset();
                Some(AssembledUpdate {
                    update_code: update.update_code,
                    data: update.update_data.clone(),
                })
            }
            Fragmentation::First => {
                // Start new reassembly; discard any incomplete previous assembly.
                self.buffer.clear();
                if update.update_data.len() > MAX_REASSEMBLY_BYTES {
                    self.reset();
                    return None;
                }
                self.buffer.extend_from_slice(&update.update_data);
                self.update_code = Some(update.update_code);
                None
            }
            Fragmentation::Next => {
                // Append to reassembly buffer.
                if self.update_code.is_some() {
                    let new_total = self.buffer.len() + update.update_data.len();
                    if new_total > MAX_REASSEMBLY_BYTES {
                        self.reset();
                        return None;
                    }
                    self.buffer.extend_from_slice(&update.update_data);
                }
                // Else: NEXT without prior FIRST -- discard silently.
                None
            }
            Fragmentation::Last => {
                // Final fragment; complete the reassembly.
                if let Some(update_code) = self.update_code.take() {
                    let new_total = self.buffer.len() + update.update_data.len();
                    if new_total > MAX_REASSEMBLY_BYTES {
                        self.reset();
                        return None;
                    }
                    self.buffer.extend_from_slice(&update.update_data);
                    let data = core::mem::take(&mut self.buffer);
                    Some(AssembledUpdate { update_code, data })
                } else {
                    // LAST without prior FIRST -- discard silently.
                    None
                }
            }
        }
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.update_code = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn make_update(
        update_code: FastPathUpdateType,
        frag: Fragmentation,
        data: &[u8],
    ) -> FastPathOutputUpdate {
        FastPathOutputUpdate {
            update_code,
            fragmentation: frag,
            compression: 0,
            compression_flags: None,
            update_data: data.to_vec(),
        }
    }

    #[test]
    fn single_fragment_dispatches_immediately() {
        let mut cd = CompleteData::new();
        let update = make_update(FastPathUpdateType::Bitmap, Fragmentation::Single, b"bitmap_data");
        let result = cd.process_update(&update);
        assert!(result.is_some());
        let assembled = result.unwrap();
        assert_eq!(assembled.update_code, FastPathUpdateType::Bitmap);
        assert_eq!(assembled.data, b"bitmap_data");
    }

    #[test]
    fn multi_fragment_reassembly() {
        let mut cd = CompleteData::new();

        let first = make_update(FastPathUpdateType::Orders, Fragmentation::First, b"AAA");
        assert!(cd.process_update(&first).is_none());

        let next = make_update(FastPathUpdateType::Orders, Fragmentation::Next, b"BBB");
        assert!(cd.process_update(&next).is_none());

        let last = make_update(FastPathUpdateType::Orders, Fragmentation::Last, b"CCC");
        let result = cd.process_update(&last);
        assert!(result.is_some());
        let assembled = result.unwrap();
        assert_eq!(assembled.update_code, FastPathUpdateType::Orders);
        assert_eq!(assembled.data, b"AAABBBCCC");
    }

    #[test]
    fn last_without_first_is_discarded() {
        let mut cd = CompleteData::new();
        let last = make_update(FastPathUpdateType::Bitmap, Fragmentation::Last, b"orphan");
        assert!(cd.process_update(&last).is_none());
    }

    #[test]
    fn next_without_first_is_discarded() {
        let mut cd = CompleteData::new();
        let next = make_update(FastPathUpdateType::Bitmap, Fragmentation::Next, b"orphan");
        assert!(cd.process_update(&next).is_none());
    }

    #[test]
    fn new_first_discards_incomplete_assembly() {
        let mut cd = CompleteData::new();

        // Start one assembly...
        let first1 = make_update(FastPathUpdateType::Orders, Fragmentation::First, b"old");
        assert!(cd.process_update(&first1).is_none());

        // Start a new one (old is discarded).
        let first2 = make_update(FastPathUpdateType::Bitmap, Fragmentation::First, b"new");
        assert!(cd.process_update(&first2).is_none());

        let last = make_update(FastPathUpdateType::Bitmap, Fragmentation::Last, b"end");
        let result = cd.process_update(&last).unwrap();
        assert_eq!(result.update_code, FastPathUpdateType::Bitmap);
        assert_eq!(result.data, b"newend");
    }

    #[test]
    fn first_last_only() {
        let mut cd = CompleteData::new();

        let first = make_update(FastPathUpdateType::SurfaceCommands, Fragmentation::First, b"AB");
        assert!(cd.process_update(&first).is_none());

        let last = make_update(FastPathUpdateType::SurfaceCommands, Fragmentation::Last, b"CD");
        let result = cd.process_update(&last).unwrap();
        assert_eq!(result.data, b"ABCD");
    }

    #[test]
    fn single_during_assembly_resets_state() {
        let mut cd = CompleteData::new();

        // Start assembly...
        let first = make_update(FastPathUpdateType::Orders, Fragmentation::First, b"partial");
        assert!(cd.process_update(&first).is_none());

        // A Single should dispatch immediately, discarding the partial assembly.
        let single = make_update(FastPathUpdateType::Bitmap, Fragmentation::Single, b"complete");
        let result = cd.process_update(&single).unwrap();
        assert_eq!(result.update_code, FastPathUpdateType::Bitmap);
        assert_eq!(result.data, b"complete");

        // Verify the old assembly was discarded: a Last without a First should be dropped.
        let orphan_last = make_update(FastPathUpdateType::Orders, Fragmentation::Last, b"stale");
        assert!(cd.process_update(&orphan_last).is_none());
    }

    #[test]
    fn first_fragment_exceeding_cap_is_discarded() {
        let mut cd = CompleteData::new();

        let oversized = vec![0u8; MAX_REASSEMBLY_BYTES + 1];
        let update = make_update(FastPathUpdateType::Bitmap, Fragmentation::First, &oversized);
        assert!(cd.process_update(&update).is_none());

        // State should be fully reset — a subsequent Last should not produce output.
        let last = make_update(FastPathUpdateType::Bitmap, Fragmentation::Last, b"end");
        assert!(cd.process_update(&last).is_none());
    }

    #[test]
    fn next_fragment_pushing_over_cap_resets_state() {
        let mut cd = CompleteData::new();

        // Start within budget.
        let first_data = vec![0u8; MAX_REASSEMBLY_BYTES - 10];
        let first = make_update(FastPathUpdateType::Bitmap, Fragmentation::First, &first_data);
        assert!(cd.process_update(&first).is_none());

        // Push over limit.
        let next_data = vec![0u8; 20];
        let next = make_update(FastPathUpdateType::Bitmap, Fragmentation::Next, &next_data);
        assert!(cd.process_update(&next).is_none());

        // State should be reset — Last won't produce output.
        let last = make_update(FastPathUpdateType::Bitmap, Fragmentation::Last, b"end");
        assert!(cd.process_update(&last).is_none());

        // A new assembly should work after reset.
        let fresh_first = make_update(FastPathUpdateType::Orders, Fragmentation::First, b"A");
        assert!(cd.process_update(&fresh_first).is_none());
        let fresh_last = make_update(FastPathUpdateType::Orders, Fragmentation::Last, b"B");
        let result = cd.process_update(&fresh_last).unwrap();
        assert_eq!(result.data, b"AB");
    }

    #[test]
    fn last_fragment_pushing_over_cap_resets_state() {
        let mut cd = CompleteData::new();

        let first_data = vec![0u8; MAX_REASSEMBLY_BYTES - 10];
        let first = make_update(FastPathUpdateType::Bitmap, Fragmentation::First, &first_data);
        assert!(cd.process_update(&first).is_none());

        // Last fragment itself pushes total over limit.
        let last_data = vec![0u8; 20];
        let last = make_update(FastPathUpdateType::Bitmap, Fragmentation::Last, &last_data);
        assert!(cd.process_update(&last).is_none());
    }
}
