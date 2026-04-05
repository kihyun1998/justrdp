#![forbid(unsafe_code)]

//! Virtual channel dechunking (reassembly) -- MS-RDPBCGR 3.1.5.2.2.1
//!
//! Reassembles fragmented virtual channel messages from individual chunks
//! identified by CHANNEL_FLAG_FIRST / CHANNEL_FLAG_LAST flags.

use alloc::vec::Vec;

use justrdp_pdu::rdp::svc::{CHANNEL_FLAG_FIRST, CHANNEL_FLAG_LAST};

use crate::{SvcError, SvcResult};

/// Maximum reassembly buffer size (64 MiB safety cap).
const MAX_REASSEMBLY_SIZE: u32 = 64 * 1024 * 1024;

/// Initial reservation cap for multi-chunk reassembly (64 KiB).
/// Prevents memory amplification from adversarial FIRST PDUs declaring large total_length.
const INITIAL_REASSEMBLY_RESERVE: usize = 64 * 1024;

/// Per-channel dechunking state machine.
#[derive(Debug)]
pub(crate) struct Dechunker {
    /// Reassembly buffer (active only during multi-chunk assembly).
    buffer: Vec<u8>,
    /// Total expected uncompressed length from the FIRST chunk's header.
    total_length: u32,
    /// Whether we are currently assembling fragments.
    assembling: bool,
}

impl Dechunker {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            total_length: 0,
            assembling: false,
        }
    }

    /// Process a single chunk and return the complete message when ready.
    ///
    /// `total_length` is from `ChannelPduHeader::length` (same in every chunk).
    /// `flags` is from `ChannelPduHeader::flags`.
    /// `chunk_data` is the virtual channel data after the header.
    pub fn process_chunk(
        &mut self,
        total_length: u32,
        flags: u32,
        chunk_data: &[u8],
    ) -> SvcResult<Option<Vec<u8>>> {
        let is_first = flags & CHANNEL_FLAG_FIRST != 0;
        let is_last = flags & CHANNEL_FLAG_LAST != 0;

        if is_first {
            // Start new reassembly (discard any incomplete prior assembly).
            if total_length > MAX_REASSEMBLY_SIZE {
                return Err(SvcError::Protocol(alloc::format!(
                    "channel message too large: {total_length} bytes"
                )));
            }
            self.buffer.clear();
            self.total_length = total_length;

            if is_last {
                // Single-chunk message: FIRST + LAST.
                let chunk_len = u32::try_from(chunk_data.len()).map_err(|_| {
                    SvcError::Protocol(alloc::format!(
                        "chunk data too large: {} bytes",
                        chunk_data.len()
                    ))
                })?;
                if chunk_len != total_length {
                    return Err(SvcError::Protocol(alloc::format!(
                        "single-chunk size mismatch: expected {}, got {}",
                        total_length,
                        chunk_data.len()
                    )));
                }
                self.assembling = false;
                return Ok(Some(chunk_data.to_vec()));
            }

            // Multi-chunk: start assembling.
            // Validate first chunk data doesn't exceed declared total.
            if chunk_data.len() > total_length as usize {
                return Err(SvcError::Protocol(alloc::format!(
                    "first chunk data ({}) exceeds declared total_length ({})",
                    chunk_data.len(),
                    total_length
                )));
            }
            self.buffer.reserve(core::cmp::min(total_length as usize, INITIAL_REASSEMBLY_RESERVE));
            self.buffer.extend_from_slice(chunk_data);
            self.assembling = true;
            Ok(None)
        } else if is_last {
            // Final chunk of a multi-chunk sequence.
            if !self.assembling {
                // LAST without prior FIRST -- protocol violation; discard.
                return Ok(None);
            }
            let new_len = self.buffer.len().checked_add(chunk_data.len()).ok_or_else(|| {
                SvcError::Protocol(alloc::string::String::from("chunk length overflow"))
            })?;
            if new_len > self.total_length as usize {
                self.reset();
                return Err(SvcError::Protocol(alloc::format!(
                    "channel data exceeds declared total_length: {} > {}",
                    new_len,
                    self.total_length
                )));
            }
            self.buffer.extend_from_slice(chunk_data);
            self.assembling = false;
            let assembled = core::mem::take(&mut self.buffer);
            let expected = self.total_length;
            // Validate total assembled length matches the declared total.
            if assembled.len() != expected as usize {
                self.total_length = 0;
                return Err(SvcError::Protocol(alloc::format!(
                    "channel reassembly size mismatch: expected {}, got {}",
                    expected,
                    assembled.len()
                )));
            }
            Ok(Some(assembled))
        } else if self.assembling {
            // Intermediate chunk -- enforce total_length bound.
            let new_len = self.buffer.len().checked_add(chunk_data.len()).ok_or_else(|| {
                SvcError::Protocol(alloc::string::String::from("chunk length overflow"))
            })?;
            if new_len > self.total_length as usize {
                self.reset();
                return Err(SvcError::Protocol(alloc::format!(
                    "channel data exceeds declared total_length: {} > {}",
                    new_len,
                    self.total_length
                )));
            }
            self.buffer.extend_from_slice(chunk_data);
            Ok(None)
        } else {
            // No FIRST, no LAST, not assembling -- protocol violation; discard.
            Ok(None)
        }
    }

    /// Reset the dechunker state (e.g., on deactivation-reactivation).
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.assembling = false;
        self.total_length = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::rdp::svc::CHANNEL_FLAG_SHOW_PROTOCOL;

    #[test]
    fn single_chunk_first_last() {
        let mut d = Dechunker::new();
        let result = d
            .process_chunk(5, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST, b"hello")
            .unwrap();
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[test]
    fn multi_chunk_three_parts() {
        let mut d = Dechunker::new();
        let total = 9u32;

        // FIRST
        let r = d
            .process_chunk(total, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_SHOW_PROTOCOL, b"AAA")
            .unwrap();
        assert!(r.is_none());

        // Intermediate (no FIRST/LAST)
        let r = d
            .process_chunk(total, CHANNEL_FLAG_SHOW_PROTOCOL, b"BBB")
            .unwrap();
        assert!(r.is_none());

        // LAST
        let r = d
            .process_chunk(total, CHANNEL_FLAG_LAST | CHANNEL_FLAG_SHOW_PROTOCOL, b"CCC")
            .unwrap();
        assert_eq!(r, Some(b"AAABBBCCC".to_vec()));
    }

    #[test]
    fn no_flags_not_assembling_returns_none() {
        // No FIRST/LAST flags, not assembling -- protocol violation; silently discarded.
        let mut d = Dechunker::new();
        let result = d.process_chunk(4, 0, b"data").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn new_first_discards_incomplete() {
        let mut d = Dechunker::new();

        // Start assembly...
        d.process_chunk(100, CHANNEL_FLAG_FIRST, b"old").unwrap();

        // New FIRST discards old.
        d.process_chunk(6, CHANNEL_FLAG_FIRST, b"new").unwrap();
        let r = d.process_chunk(6, CHANNEL_FLAG_LAST, b"end").unwrap();
        assert_eq!(r, Some(b"newend".to_vec()));
    }

    #[test]
    fn oversized_message_rejected() {
        let mut d = Dechunker::new();
        let result = d.process_chunk(MAX_REASSEMBLY_SIZE + 1, CHANNEL_FLAG_FIRST, b"x");
        assert!(result.is_err());
    }

    #[test]
    fn reset_clears_state() {
        let mut d = Dechunker::new();
        d.process_chunk(100, CHANNEL_FLAG_FIRST, b"partial").unwrap();
        d.reset();
        // After reset, a proper FIRST+LAST works normally.
        let r = d
            .process_chunk(4, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST, b"data")
            .unwrap();
        assert_eq!(r, Some(b"data".to_vec()));
    }

    #[test]
    fn last_without_first_returns_none() {
        // LAST without prior FIRST is a protocol violation; silently discarded.
        let mut d = Dechunker::new();
        let r = d.process_chunk(5, CHANNEL_FLAG_LAST, b"alone").unwrap();
        assert_eq!(r, None);
    }

    #[test]
    fn single_chunk_length_mismatch_rejected() {
        let mut d = Dechunker::new();
        // total_length says 100 but only 3 bytes of data.
        let result = d.process_chunk(100, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST, b"abc");
        assert!(result.is_err());
    }

    #[test]
    fn multi_chunk_length_mismatch_rejected() {
        let mut d = Dechunker::new();
        // Declare total_length = 10, but send only 6 bytes total.
        d.process_chunk(10, CHANNEL_FLAG_FIRST, b"AAA").unwrap();
        let result = d.process_chunk(10, CHANNEL_FLAG_LAST, b"BBB");
        assert!(result.is_err());
    }

    #[test]
    fn intermediate_chunk_exceeds_total_length_rejected() {
        let mut d = Dechunker::new();
        // Declare total_length = 6, then try to exceed it with intermediate chunks.
        d.process_chunk(6, CHANNEL_FLAG_FIRST, b"AAA").unwrap();
        // This intermediate chunk would make buffer 7 bytes, exceeding total_length of 6.
        let result = d.process_chunk(6, 0, b"BBBB");
        assert!(result.is_err());
    }
}
