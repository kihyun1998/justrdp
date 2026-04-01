#![forbid(unsafe_code)]

//! XCRUSH bulk decompression (RDP 6.1).
//!
//! Implements the two-stage decompression pipeline described in:
//! - MS-RDPEGDI §2.2.2.4.1 (RDP61_COMPRESSED_DATA)
//! - MS-RDPEGDI §3.1.8.2.3 (Decompressing Data)
//!
//! Stage 1 (Level-2): Optional MPPC 64K decompression of the payload.
//! Stage 2 (Level-1): Match/literal reconstruction using a 2 MB linear history buffer.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::mppc::{DecompressError, Mppc64kDecompressor};

// ── Level-1 compression flags (MS-RDPEGDI §2.2.2.4.1) ──

/// MatchCount and MatchDetails are present; at least one match exists.
const L1_COMPRESSED: u8 = 0x01;

/// No L1 compression; payload is raw literals.
const L1_NO_COMPRESSION: u8 = 0x02;

/// Reset L1 history buffer to all zeros and set offset to 0.
const L1_PACKET_AT_FRONT: u8 = 0x04;

/// Payload was compressed by the Level-2 MPPC 64K compressor.
/// Level2ComprFlags byte is valid and must be processed.
const L1_INNER_COMPRESSION: u8 = 0x10;

// ── History buffer ──

/// L1 history buffer size: 2 MB (MS-RDPEGDI §3.1.8.2).
const L1_HISTORY_SIZE: usize = 2_000_000;

// ── XcrushDecompressor ──

/// XCRUSH two-stage decompressor (RDP 6.1).
///
/// Level-2: MPPC 64K decompression (optional, controlled by `L1_INNER_COMPRESSION`).
/// Level-1: Match/literal reconstruction with 2 MB linear history buffer.
pub struct XcrushDecompressor {
    l1_history: Box<[u8]>,
    l1_history_offset: usize,
    l2: Mppc64kDecompressor,
    /// Reusable buffer for Level-2 decompression output, avoiding per-call allocation.
    l2_buf: Vec<u8>,
}

impl XcrushDecompressor {
    /// Create a new decompressor with zeroed history.
    pub fn new() -> Self {
        Self {
            l1_history: vec![0u8; L1_HISTORY_SIZE].into_boxed_slice(),
            l1_history_offset: 0,
            l2: Mppc64kDecompressor::new(),
            l2_buf: Vec::new(),
        }
    }

    /// Reset L1 history and offset. Does NOT reset the L2 decompressor.
    pub fn reset_l1(&mut self) {
        self.l1_history.fill(0);
        self.l1_history_offset = 0;
    }

    /// Decompress an XCRUSH packet.
    ///
    /// `src` starts with `Level1ComprFlags` and `Level2ComprFlags` (2 bytes header),
    /// followed by the payload. The transport-layer `compressedType` nibble
    /// (`PACKET_COMPR_TYPE_RDP61 = 0x03`) has already been consumed by the caller.
    ///
    /// Decompressed output is appended to `dst`.
    pub fn decompress(
        &mut self,
        src: &[u8],
        dst: &mut Vec<u8>,
    ) -> Result<(), DecompressError> {
        // Step 1: Parse header
        if src.len() < 2 {
            return Err(DecompressError::TruncatedBitstream);
        }
        let l1_flags = src[0];
        let l2_flags = src[1];
        let payload = &src[2..];

        // Step 2: L1 history reset (before any decompression)
        if l1_flags & L1_PACKET_AT_FRONT != 0 {
            self.reset_l1();
        }

        // Step 3: L2 decompression (conditional).
        // Take the reusable buffer out of `self` to avoid borrow conflicts
        // with the L1 methods that need `&mut self`.
        let mut l2_buf = core::mem::take(&mut self.l2_buf);
        l2_buf.clear();

        let use_l2 = l1_flags & L1_INNER_COMPRESSION != 0;
        if use_l2 {
            self.l2.decompress(payload, l2_flags, &mut l2_buf)?;
        }
        let l1_input = if use_l2 { &l2_buf[..] } else { payload };

        // Step 4: L1 decompression
        let result = if l1_flags & L1_NO_COMPRESSION != 0 {
            self.copy_literals(l1_input, dst)
        } else if l1_flags & L1_COMPRESSED != 0 {
            self.decompress_l1(l1_input, dst)
        } else {
            // Neither L1_COMPRESSED nor L1_NO_COMPRESSION is set.
            // This is an unspecified protocol state — return an error
            // rather than silently treating data as raw.
            Err(DecompressError::InvalidFlags)
        };

        // Return the buffer to `self` for reuse in future calls.
        self.l2_buf = l2_buf;
        result
    }

    /// Copy raw literals into L1 history and output.
    fn copy_literals(&mut self, data: &[u8], dst: &mut Vec<u8>) -> Result<(), DecompressError> {
        if self.l1_history_offset + data.len() > L1_HISTORY_SIZE {
            return Err(DecompressError::HistoryOverflow);
        }
        self.l1_history[self.l1_history_offset..self.l1_history_offset + data.len()]
            .copy_from_slice(data);
        self.l1_history_offset += data.len();
        dst.extend_from_slice(data);
        Ok(())
    }

    /// Level-1 decompression: reconstruct output from MatchDetails + Literals.
    fn decompress_l1(
        &mut self,
        l1_input: &[u8],
        dst: &mut Vec<u8>,
    ) -> Result<(), DecompressError> {
        // Read MatchCount (u16 LE) from first 2 bytes
        if l1_input.len() < 2 {
            return Err(DecompressError::TruncatedBitstream);
        }
        let match_count = u16::from_le_bytes([l1_input[0], l1_input[1]]) as usize;

        // Validate match details fit in the buffer
        let details_size = match_count.checked_mul(8).ok_or(DecompressError::TruncatedBitstream)?;
        let details_end = 2usize
            .checked_add(details_size)
            .ok_or(DecompressError::TruncatedBitstream)?;
        if l1_input.len() < details_end {
            return Err(DecompressError::TruncatedBitstream);
        }

        let literals = &l1_input[details_end..];
        let mut output_offset: usize = 0;
        let mut literals_offset: usize = 0;

        // Process each match
        for i in 0..match_count {
            let base = 2 + i * 8;
            let match_length =
                u16::from_le_bytes([l1_input[base], l1_input[base + 1]]) as usize;
            let match_output_offset =
                u16::from_le_bytes([l1_input[base + 2], l1_input[base + 3]]) as usize;
            let match_history_offset = u32::from_le_bytes([
                l1_input[base + 4],
                l1_input[base + 5],
                l1_input[base + 6],
                l1_input[base + 7],
            ]) as usize;

            // Reject out-of-order matches (spec requires ascending MatchOutputOffset)
            if match_output_offset < output_offset {
                return Err(DecompressError::InvalidCopyOffset);
            }

            // Fill gap with literals before this match
            if match_output_offset > output_offset {
                let gap = match_output_offset - output_offset;
                if literals_offset + gap > literals.len() {
                    return Err(DecompressError::TruncatedBitstream);
                }
                let literal_data = &literals[literals_offset..literals_offset + gap];
                if self.l1_history_offset + gap > L1_HISTORY_SIZE {
                    return Err(DecompressError::HistoryOverflow);
                }
                self.l1_history[self.l1_history_offset..self.l1_history_offset + gap]
                    .copy_from_slice(literal_data);
                self.l1_history_offset += gap;
                dst.extend_from_slice(literal_data);
                output_offset += gap;
                literals_offset += gap;
            }

            // Validate match source
            if match_history_offset + match_length > L1_HISTORY_SIZE {
                return Err(DecompressError::HistoryOverflow);
            }
            if self.l1_history_offset + match_length > L1_HISTORY_SIZE {
                return Err(DecompressError::HistoryOverflow);
            }

            // Copy match from history (byte-by-byte for potential overlap)
            for j in 0..match_length {
                let b = self.l1_history[match_history_offset + j];
                self.l1_history[self.l1_history_offset] = b;
                self.l1_history_offset += 1;
                dst.push(b);
            }
            output_offset += match_length;
        }

        // Copy remaining literals after last match
        if literals_offset < literals.len() {
            let remaining = &literals[literals_offset..];
            if self.l1_history_offset + remaining.len() > L1_HISTORY_SIZE {
                return Err(DecompressError::HistoryOverflow);
            }
            self.l1_history[self.l1_history_offset..self.l1_history_offset + remaining.len()]
                .copy_from_slice(remaining);
            self.l1_history_offset += remaining.len();
            dst.extend_from_slice(remaining);
        }

        Ok(())
    }
}

impl Default for XcrushDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for XcrushDecompressor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XcrushDecompressor")
            .field("l1_history_offset", &self.l1_history_offset)
            .field("l2", &self.l2)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Spec test vectors (MS-RDPEGDI §2.2.2.4.2 / §3.1.8.2.3.1) ──

    /// Packet 1: L1_NO_COMPRESSION + L1_PACKET_AT_FRONT + L1_INNER_COMPRESSION
    /// with PACKET_FLUSHED in Level2ComprFlags.
    /// Payload: "abcdefghij"
    #[test]
    fn spec_packet1_no_compression() {
        let wire: &[u8] = &[
            0x16, // L1_INNER_COMPRESSION | L1_NO_COMPRESSION | L1_PACKET_AT_FRONT
            0x80, // PACKET_FLUSHED (L2)
            // Payload: raw "abcdefghij" (L2 not compressed, just flushed)
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
        ];

        let mut dec = XcrushDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(wire, &mut out).unwrap();

        assert_eq!(out, b"abcdefghij");
        assert_eq!(dec.l1_history_offset, 10);
        assert_eq!(&dec.l1_history[..10], b"abcdefghij");
    }

    /// Packet 2: L1_COMPRESSED + L1_INNER_COMPRESSION with 2 matches.
    /// This tests the L1 decompression in isolation (passing L1 input directly).
    #[test]
    fn spec_packet2_compressed_l1_only() {
        // Set up history from packet 1
        let mut dec = XcrushDecompressor::new();
        dec.l1_history[..10].copy_from_slice(b"abcdefghij");
        dec.l1_history_offset = 10;

        // L1 input after L2 decompression (from spec example):
        // MatchCount=2, then 2 match details, then literals "klmnou"
        let l1_input: &[u8] = &[
            // MatchCount = 2 (u16 LE)
            0x02, 0x00,
            // Match[0]: length=9, output_offset=5, history_offset=3
            0x09, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00,
            // Match[1]: length=4, output_offset=14, history_offset=0
            0x04, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Literals: "klmnou"
            0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x75,
        ];

        let mut out = Vec::new();
        dec.decompress_l1(l1_input, &mut out).unwrap();

        // Expected output: "klmnodefghijklabcdu"
        assert_eq!(out, b"klmnodefghijklabcdu");
        assert_eq!(dec.l1_history_offset, 29);
        assert_eq!(&dec.l1_history[..29], b"abcdefghijklmnodefghijklabcdu");
    }

    /// Full two-packet sequence through the public API.
    #[test]
    fn spec_two_packet_sequence() {
        let mut dec = XcrushDecompressor::new();

        // Packet 1: no compression, with L2 flush
        let pkt1: &[u8] = &[
            0x16, 0x80, // flags
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
        ];
        let mut out1 = Vec::new();
        dec.decompress(pkt1, &mut out1).unwrap();
        assert_eq!(out1, b"abcdefghij");

        // Packet 2: L1_COMPRESSED + L1_INNER_COMPRESSION
        // Since L2 flags = 0x21 (PACKET_COMPRESSED | TYPE_64K), the payload
        // would normally be MPPC-compressed. For this test we simulate by
        // directly constructing the wire bytes WITHOUT actual MPPC compression.
        // We use L1_COMPRESSED WITHOUT L1_INNER_COMPRESSION to bypass L2.
        let pkt2: &[u8] = &[
            0x01, // L1_COMPRESSED only (no L1_INNER_COMPRESSION)
            0x00, // Level2ComprFlags (ignored since no L1_INNER_COMPRESSION)
            // L1 payload: same as spec_packet2_compressed_l1_only
            0x02, 0x00,
            0x09, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x75,
        ];
        let mut out2 = Vec::new();
        dec.decompress(pkt2, &mut out2).unwrap();
        assert_eq!(out2, b"klmnodefghijklabcdu");
    }

    // ── Flag handling tests ──

    #[test]
    fn l1_packet_at_front_resets_history() {
        let mut dec = XcrushDecompressor::new();
        // Fill some history
        dec.l1_history[..5].copy_from_slice(b"hello");
        dec.l1_history_offset = 5;

        // Packet with L1_PACKET_AT_FRONT + L1_NO_COMPRESSION
        let pkt: &[u8] = &[
            L1_PACKET_AT_FRONT | L1_NO_COMPRESSION,
            0x00, // Level2ComprFlags (ignored)
            0x41, 0x42, // "AB"
        ];
        let mut out = Vec::new();
        dec.decompress(pkt, &mut out).unwrap();

        assert_eq!(out, b"AB");
        assert_eq!(dec.l1_history_offset, 2);
        // History was reset, so "hello" is gone
        assert_eq!(&dec.l1_history[..2], b"AB");
    }

    #[test]
    fn l2_flush_does_not_affect_l1() {
        let mut dec = XcrushDecompressor::new();
        dec.l1_history[..3].copy_from_slice(b"abc");
        dec.l1_history_offset = 3;

        // L1_INNER_COMPRESSION + L1_NO_COMPRESSION, L2 = PACKET_FLUSHED
        let pkt: &[u8] = &[
            L1_INNER_COMPRESSION | L1_NO_COMPRESSION,
            0x80, // PACKET_FLUSHED
            0x58, 0x59, // "XY"
        ];
        let mut out = Vec::new();
        dec.decompress(pkt, &mut out).unwrap();

        assert_eq!(out, b"XY");
        // L1 history preserved from before + new data
        assert_eq!(dec.l1_history_offset, 5);
        assert_eq!(&dec.l1_history[..5], b"abcXY");
    }

    // ── Error condition tests ──

    #[test]
    fn truncated_header() {
        let mut dec = XcrushDecompressor::new();
        let mut out = Vec::new();
        let result = dec.decompress(&[0x01], &mut out);
        assert_eq!(result, Err(DecompressError::TruncatedBitstream));
    }

    #[test]
    fn truncated_match_details() {
        let mut dec = XcrushDecompressor::new();
        // L1_COMPRESSED, MatchCount=5 but only 10 bytes of payload
        let pkt: &[u8] = &[
            L1_COMPRESSED,
            0x00,
            // MatchCount = 5
            0x05, 0x00,
            // Only 6 bytes of match data (need 5*8=40)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut out = Vec::new();
        let result = dec.decompress(pkt, &mut out);
        assert_eq!(result, Err(DecompressError::TruncatedBitstream));
    }

    #[test]
    fn match_history_offset_out_of_bounds() {
        let mut dec = XcrushDecompressor::new();
        dec.l1_history[..5].copy_from_slice(b"hello");
        dec.l1_history_offset = 5;

        // Match references beyond L1_HISTORY_SIZE
        let pkt: &[u8] = &[
            L1_COMPRESSED,
            0x00,
            // MatchCount = 1
            0x01, 0x00,
            // Match: length=10, output_offset=0, history_offset=L1_HISTORY_SIZE-5
            0x0A, 0x00, 0x00, 0x00,
            ((L1_HISTORY_SIZE - 5) & 0xFF) as u8,
            (((L1_HISTORY_SIZE - 5) >> 8) & 0xFF) as u8,
            (((L1_HISTORY_SIZE - 5) >> 16) & 0xFF) as u8,
            (((L1_HISTORY_SIZE - 5) >> 24) & 0xFF) as u8,
        ];
        let mut out = Vec::new();
        let result = dec.decompress(pkt, &mut out);
        assert_eq!(result, Err(DecompressError::HistoryOverflow));
    }

    #[test]
    fn empty_literals_all_from_history() {
        let mut dec = XcrushDecompressor::new();
        dec.l1_history[..5].copy_from_slice(b"hello");
        dec.l1_history_offset = 5;

        // Match at output_offset=0, copies 5 bytes from history[0]
        let pkt: &[u8] = &[
            L1_COMPRESSED,
            0x00,
            // MatchCount = 1
            0x01, 0x00,
            // Match: length=5, output_offset=0, history_offset=0
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // No literals
        ];
        let mut out = Vec::new();
        dec.decompress(pkt, &mut out).unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(dec.l1_history_offset, 10);
    }

    #[test]
    fn no_compression_raw_passthrough() {
        let mut dec = XcrushDecompressor::new();
        let pkt: &[u8] = &[
            L1_NO_COMPRESSION,
            0x00,
            0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
        ];
        let mut out = Vec::new();
        dec.decompress(pkt, &mut out).unwrap();
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn out_of_order_match_output_offset_rejected() {
        let mut dec = XcrushDecompressor::new();
        dec.l1_history[..10].copy_from_slice(b"abcdefghij");
        dec.l1_history_offset = 10;

        // Two matches where second has a LOWER MatchOutputOffset than first's end
        let pkt: &[u8] = &[
            L1_COMPRESSED,
            0x00,
            // MatchCount = 2
            0x02, 0x00,
            // Match[0]: length=5, output_offset=0, history_offset=0
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Match[1]: length=3, output_offset=2 (< 5, out of order!), history_offset=0
            0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut out = Vec::new();
        let result = dec.decompress(pkt, &mut out);
        assert_eq!(result, Err(DecompressError::InvalidCopyOffset));
    }
}
