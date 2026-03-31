#![forbid(unsafe_code)]

//! Fast-Path fragment reassembly -- MS-RDPBCGR 2.2.9.1.2.1
//!
//! Updates can be fragmented across multiple `FastPathOutputUpdate` PDUs.
//! This module reassembles them into complete logical updates.

use alloc::vec::Vec;

use justrdp_pdu::rdp::fast_path::{FastPathOutputUpdate, FastPathUpdateType, Fragmentation};

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

impl CompleteData {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            update_code: None,
        }
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
                self.buffer.extend_from_slice(&update.update_data);
                self.update_code = Some(update.update_code);
                None
            }
            Fragmentation::Next => {
                // Append to reassembly buffer.
                if self.update_code.is_some() {
                    self.buffer.extend_from_slice(&update.update_data);
                }
                // Else: NEXT without prior FIRST -- discard silently.
                None
            }
            Fragmentation::Last => {
                // Final fragment; complete the reassembly.
                if let Some(update_code) = self.update_code.take() {
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
}
