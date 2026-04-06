#![forbid(unsafe_code)]

//! Per-channel DVC data reassembly -- MS-RDPEDYC 3.1.5.1.2
//!
//! Reassembles fragmented DVC messages from DataFirst + Data sequences.

use alloc::vec::Vec;

use crate::{DvcError, DvcResult};

/// Maximum reassembly buffer size (16 MiB safety cap).
const MAX_REASSEMBLY_SIZE: u32 = 16 * 1024 * 1024;

/// Per-channel reassembly state.
#[derive(Debug)]
pub(crate) struct DvcReassembler {
    buffer: Vec<u8>,
    expected_length: u32,
    assembling: bool,
}

impl DvcReassembler {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            expected_length: 0,
            assembling: false,
        }
    }

    /// Process a DataFirst PDU. Starts reassembly.
    ///
    /// Returns `Some(complete_payload)` if the entire message fits in this single PDU.
    pub fn data_first(&mut self, total_length: u32, data: &[u8]) -> DvcResult<Option<Vec<u8>>> {
        if total_length > MAX_REASSEMBLY_SIZE {
            return Err(DvcError::Protocol(alloc::format!(
                "DVC message too large: {total_length} bytes"
            )));
        }

        // Discard any incomplete prior assembly.
        self.buffer.clear();
        self.expected_length = total_length;

        if data.len() >= total_length as usize {
            // Complete message in a single DataFirst.
            self.assembling = false;
            Ok(Some(data[..total_length as usize].to_vec()))
        } else {
            self.buffer.reserve(total_length as usize);
            self.buffer.extend_from_slice(data);
            self.assembling = true;
            Ok(None)
        }
    }

    /// Process a Data PDU. Appends to current reassembly.
    ///
    /// Returns `Some(complete_payload)` when reassembly is complete.
    pub fn data(&mut self, data: &[u8]) -> DvcResult<Option<Vec<u8>>> {
        if !self.assembling {
            // MS-RDPEDYC 3.1.5.2.2: standalone DYNVC_DATA without prior DataFirst
            // is a valid complete single message (data ≤ 1590 bytes).
            if data.len() > MAX_REASSEMBLY_SIZE as usize {
                return Err(DvcError::Protocol(alloc::format!(
                    "DVC standalone message too large: {} bytes", data.len()
                )));
            }
            return Ok(Some(data.to_vec()));
        }

        // Guard against buffer growing beyond expected_length.
        let space = self.expected_length as usize - self.buffer.len();
        self.buffer.extend_from_slice(&data[..data.len().min(space)]);

        if self.buffer.len() >= self.expected_length as usize {
            self.assembling = false;
            let result = self.buffer[..self.expected_length as usize].to_vec();
            self.buffer.clear();
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_data_first_complete() {
        let mut r = DvcReassembler::new();
        let result = r.data_first(5, b"hello").unwrap();
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[test]
    fn fragmented_reassembly() {
        let mut r = DvcReassembler::new();
        assert!(r.data_first(9, b"AAA").unwrap().is_none());
        assert!(r.data(b"BBB").unwrap().is_none());
        let result = r.data(b"CCC").unwrap();
        assert_eq!(result, Some(b"AAABBBCCC".to_vec()));
    }

    #[test]
    fn data_without_data_first_is_single() {
        let mut r = DvcReassembler::new();
        let result = r.data(b"standalone").unwrap();
        assert_eq!(result, Some(b"standalone".to_vec()));
    }

    #[test]
    fn new_data_first_discards_incomplete() {
        let mut r = DvcReassembler::new();
        r.data_first(100, b"old").unwrap();
        // New DataFirst discards the old incomplete assembly.
        let result = r.data_first(3, b"new").unwrap();
        assert_eq!(result, Some(b"new".to_vec()));
    }

    #[test]
    fn oversized_message_rejected() {
        let mut r = DvcReassembler::new();
        let result = r.data_first(MAX_REASSEMBLY_SIZE + 1, b"x");
        assert!(result.is_err());
    }

    #[test]
    fn new_reassembler_after_close() {
        // On channel close, the reassembler is removed entirely.
        // A new reassembler treats Data without DataFirst as single.
        let r = DvcReassembler::new();
        assert!(!r.assembling);
    }

    #[test]
    fn data_first_with_excess_data_truncates() {
        let mut r = DvcReassembler::new();
        let result = r.data_first(3, b"abcde").unwrap();
        // Only takes first 3 bytes.
        assert_eq!(result, Some(b"abc".to_vec()));
    }
}
