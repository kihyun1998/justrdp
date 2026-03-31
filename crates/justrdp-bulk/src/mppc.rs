#![forbid(unsafe_code)]

//! MPPC bulk decompression (RDP 4.0 8K / RDP 5.0 64K).
//!
//! Implements the decompression algorithm described in:
//! - MS-RDPBCGR §3.1.8.4.1 (8K variant)
//! - MS-RDPBCGR §3.1.8.4.2 (64K variant)
//! - RFC 2118 (Microsoft Point-to-Point Compression Protocol)

use alloc::vec::Vec;
use core::fmt;

// ── Compression flag constants (MS-RDPBCGR §2.2.8.1.1.1.2) ──

/// Payload is compressed (MPPC RFC 2118 bit C).
pub const PACKET_COMPRESSED: u8 = 0x20;

/// Decompress into front of history buffer (MPPC RFC 2118 bit B).
/// MUST co-occur with `PACKET_COMPRESSED`.
pub const PACKET_AT_FRONT: u8 = 0x40;

/// Reinitialize history buffer to all zeros (MPPC RFC 2118 bit A).
/// Processed before `PACKET_COMPRESSED`.
pub const PACKET_FLUSHED: u8 = 0x80;

/// Mask for compression type nibble.
pub const COMPRESSION_TYPE_MASK: u8 = 0x0F;

/// RDP 4.0 MPPC 8K history (MS-RDPBCGR §3.1.8.4.1).
pub const PACKET_COMPR_TYPE_8K: u8 = 0x0;

/// RDP 5.0 MPPC 64K history (MS-RDPBCGR §3.1.8.4.2).
pub const PACKET_COMPR_TYPE_64K: u8 = 0x1;

// ── History buffer sizes ──

const HISTORY_SIZE_8K: usize = 8_192;
const HISTORY_SIZE_64K: usize = 65_536;

// ── Error type ──

/// Decompression error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompressError {
    /// Bitstream ended in the middle of a token.
    TruncatedBitstream,
    /// Decoded copy-offset is zero (invalid).
    InvalidCopyOffset,
    /// Decompressed output exceeds history buffer size.
    HistoryOverflow,
}

impl fmt::Display for DecompressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedBitstream => write!(f, "MPPC: truncated bitstream"),
            Self::InvalidCopyOffset => write!(f, "MPPC: invalid copy offset (zero)"),
            Self::HistoryOverflow => write!(f, "MPPC: history buffer overflow"),
        }
    }
}

// ── Bitstream reader (MSB-first) ──

pub(crate) struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    /// Bits remaining in the current accumulator.
    bits_left: u32,
    /// Accumulator; valid bits are at the MSB end.
    acc: u32,
}

impl<'a> BitReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        let mut reader = Self {
            data,
            byte_pos: 0,
            bits_left: 0,
            acc: 0,
        };
        reader.fill();
        reader
    }

    /// Fill the accumulator from the input bytes.
    pub(crate) fn fill(&mut self) {
        while self.bits_left <= 24 && self.byte_pos < self.data.len() {
            self.acc |= (self.data[self.byte_pos] as u32) << (24 - self.bits_left);
            self.bits_left += 8;
            self.byte_pos += 1;
        }
    }

    /// Number of bits still available (accumulator + unread bytes).
    pub(crate) fn remaining(&self) -> u32 {
        self.bits_left + ((self.data.len() - self.byte_pos) as u32) * 8
    }

    /// Peek at the top `n` bits without consuming them.
    pub(crate) fn peek(&self, n: u32) -> u32 {
        debug_assert!(n <= 32 && n > 0);
        self.acc >> (32 - n)
    }

    /// Consume `n` bits and return them.
    pub(crate) fn read_bits(&mut self, n: u32) -> Result<u32, DecompressError> {
        if self.remaining() < n {
            return Err(DecompressError::TruncatedBitstream);
        }
        let val = self.peek(n);
        self.acc <<= n;
        self.bits_left = self.bits_left.saturating_sub(n);
        self.fill();
        Ok(val)
    }

    /// Check if any bits remain.
    pub(crate) fn has_bits(&self) -> bool {
        self.remaining() > 0
    }
}

// ── MPPC 8K Decompressor (MS-RDPBCGR §3.1.8.4.1) ──

/// MPPC 8K sliding-window decompressor (RDP 4.0).
#[derive(Debug)]
pub struct Mppc8kDecompressor {
    history: [u8; HISTORY_SIZE_8K],
    offset: usize,
}

impl Mppc8kDecompressor {
    /// Create a new decompressor with zeroed history.
    pub fn new() -> Self {
        Self {
            history: [0u8; HISTORY_SIZE_8K],
            offset: 0,
        }
    }

    /// Reinitialize history buffer and offset.
    pub fn reset(&mut self) {
        self.history.fill(0);
        self.offset = 0;
    }

    /// Decompress a packet.
    ///
    /// `src` is the compressed (or uncompressed) payload.
    /// `flags` is the `compressedType` / `compressionFlags` byte.
    /// Decompressed output is appended to `dst`.
    pub fn decompress(
        &mut self,
        src: &[u8],
        flags: u8,
        dst: &mut Vec<u8>,
    ) -> Result<(), DecompressError> {
        // Step 1: PACKET_FLUSHED — zero history, reset offset (MS-RDPBCGR §3.1.8.3)
        if flags & PACKET_FLUSHED != 0 {
            self.reset();
        }

        // Step 2: PACKET_AT_FRONT — reset offset only (buffer content preserved)
        if flags & PACKET_AT_FRONT != 0 {
            self.offset = 0;
        }

        // Step 3: Decompress or copy literal
        if flags & PACKET_COMPRESSED != 0 {
            decompress_bitstream::<HISTORY_SIZE_8K>(
                src,
                &mut self.history,
                &mut self.offset,
                dst,
            )
        } else {
            // Uncompressed: copy verbatim into history
            copy_literal(src, &mut self.history, &mut self.offset, HISTORY_SIZE_8K, dst)
        }
    }
}

impl Default for Mppc8kDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

// ── MPPC 64K Decompressor (MS-RDPBCGR §3.1.8.4.2) ──

/// MPPC 64K sliding-window decompressor (RDP 5.0).
#[derive(Debug)]
pub struct Mppc64kDecompressor {
    history: [u8; HISTORY_SIZE_64K],
    offset: usize,
}

impl Mppc64kDecompressor {
    /// Create a new decompressor with zeroed history.
    pub fn new() -> Self {
        Self {
            history: [0u8; HISTORY_SIZE_64K],
            offset: 0,
        }
    }

    /// Reinitialize history buffer and offset.
    pub fn reset(&mut self) {
        self.history.fill(0);
        self.offset = 0;
    }

    /// Decompress a packet. See [`Mppc8kDecompressor::decompress`] for details.
    pub fn decompress(
        &mut self,
        src: &[u8],
        flags: u8,
        dst: &mut Vec<u8>,
    ) -> Result<(), DecompressError> {
        if flags & PACKET_FLUSHED != 0 {
            self.reset();
        }

        if flags & PACKET_AT_FRONT != 0 {
            self.offset = 0;
        }

        if flags & PACKET_COMPRESSED != 0 {
            decompress_bitstream::<HISTORY_SIZE_64K>(
                src,
                &mut self.history,
                &mut self.offset,
                dst,
            )
        } else {
            copy_literal(src, &mut self.history, &mut self.offset, HISTORY_SIZE_64K, dst)
        }
    }
}

impl Default for Mppc64kDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

// ── Shared implementation ──

/// Copy uncompressed data into history and output.
fn copy_literal(
    src: &[u8],
    history: &mut [u8],
    offset: &mut usize,
    history_size: usize,
    dst: &mut Vec<u8>,
) -> Result<(), DecompressError> {
    if *offset + src.len() > history_size {
        return Err(DecompressError::HistoryOverflow);
    }
    history[*offset..*offset + src.len()].copy_from_slice(src);
    *offset += src.len();
    dst.extend_from_slice(src);
    Ok(())
}

/// Decompress a compressed bitstream into history and output.
///
/// `HISTORY_SIZE` must be `HISTORY_SIZE_8K` or `HISTORY_SIZE_64K`.
fn decompress_bitstream<const HISTORY_SIZE: usize>(
    src: &[u8],
    history: &mut [u8],
    offset: &mut usize,
    dst: &mut Vec<u8>,
) -> Result<(), DecompressError> {
    let mask: usize = HISTORY_SIZE - 1;
    let mut reader = BitReader::new(src);
    let start_offset = *offset;

    while reader.has_bits() {
        let top = reader.peek(1);

        if top == 0 {
            // Literal 0x00..=0x7F: prefix '0' + 7 data bits = 8 bits
            if reader.remaining() < 8 {
                break;
            }
            let val = reader.read_bits(8)? as u8; // top bit is 0, so value is in 0x00..0x7F
            if *offset >= HISTORY_SIZE {
                return Err(DecompressError::HistoryOverflow);
            }
            history[*offset] = val;
            *offset += 1;
        } else {
            // Top bit is 1
            if reader.remaining() < 2 {
                break;
            }
            let top2 = reader.peek(2);

            if top2 == 0b10 {
                // Literal 0x80..=0xFF: prefix '10' + 7 data bits = 9 bits
                if reader.remaining() < 9 {
                    break;
                }
                let bits = reader.read_bits(9)?;
                let val = (0x80 | (bits & 0x7F)) as u8;
                if *offset >= HISTORY_SIZE {
                    return Err(DecompressError::HistoryOverflow);
                }
                history[*offset] = val;
                *offset += 1;
            } else {
                // Copy token: starts with '11'
                let copy_offset = decode_copy_offset::<HISTORY_SIZE>(&mut reader)?;
                if copy_offset == 0 {
                    return Err(DecompressError::InvalidCopyOffset);
                }
                let length = decode_length_of_match::<HISTORY_SIZE>(&mut reader)?;

                if *offset + length > HISTORY_SIZE {
                    return Err(DecompressError::HistoryOverflow);
                }

                // Replicating copy (byte-by-byte for overlap support)
                let src_start = offset.wrapping_sub(copy_offset) & mask;
                for i in 0..length {
                    let src_idx = (src_start + i) & mask;
                    let b = history[src_idx];
                    history[*offset] = b;
                    *offset += 1;
                }
            }
        }
    }

    // Append the decompressed region to output
    dst.extend_from_slice(&history[start_offset..*offset]);
    Ok(())
}

/// Decode copy-offset from bitstream.
///
/// 8K variant (MS-RDPBCGR §3.1.8.4.1.2.1):
///   `1111`  + 6 bits  → offset 0..63
///   `1110`  + 8 bits  → offset 64..319
///   `110`   + 13 bits → offset 320..8191
///
/// 64K variant (MS-RDPBCGR §3.1.8.4.2.2.1):
///   `11111` + 6 bits  → offset 0..63
///   `11110` + 8 bits  → offset 64..319
///   `1110`  + 11 bits → offset 320..2367
///   `110`   + 16 bits → offset 2368..65535
fn decode_copy_offset<const HISTORY_SIZE: usize>(
    reader: &mut BitReader<'_>,
) -> Result<usize, DecompressError> {
    if HISTORY_SIZE == HISTORY_SIZE_8K {
        // Already consumed nothing; we know top 2 bits are '11'
        // Check for '110' (3 bits)
        if reader.remaining() < 3 {
            return Err(DecompressError::TruncatedBitstream);
        }
        let top3 = reader.peek(3);
        if top3 == 0b110 {
            // 110 + 13 bits → offset 320..8191
            if reader.remaining() < 16 {
                return Err(DecompressError::TruncatedBitstream);
            }
            reader.read_bits(3)?;
            let payload = reader.read_bits(13)? as usize;
            return Ok(payload + 320);
        }

        // Check for '1110' or '1111' (4 bits)
        if reader.remaining() < 4 {
            return Err(DecompressError::TruncatedBitstream);
        }
        let top4 = reader.peek(4);
        if top4 == 0b1110 {
            // 1110 + 8 bits → offset 64..319
            if reader.remaining() < 12 {
                return Err(DecompressError::TruncatedBitstream);
            }
            reader.read_bits(4)?;
            let payload = reader.read_bits(8)? as usize;
            Ok(payload + 64)
        } else {
            // 1111 + 6 bits → offset 0..63
            if reader.remaining() < 10 {
                return Err(DecompressError::TruncatedBitstream);
            }
            reader.read_bits(4)?;
            let payload = reader.read_bits(6)? as usize;
            Ok(payload)
        }
    } else {
        // 64K variant
        // Check for '110' (3 bits)
        if reader.remaining() < 3 {
            return Err(DecompressError::TruncatedBitstream);
        }
        let top3 = reader.peek(3);
        if top3 == 0b110 {
            // 110 + 16 bits → offset 2368..65535
            if reader.remaining() < 19 {
                return Err(DecompressError::TruncatedBitstream);
            }
            reader.read_bits(3)?;
            let payload = reader.read_bits(16)? as usize;
            return Ok(payload + 2368);
        }

        // Check for '1110' (4 bits)
        if reader.remaining() < 4 {
            return Err(DecompressError::TruncatedBitstream);
        }
        let top4 = reader.peek(4);
        if top4 == 0b1110 {
            // 1110 + 11 bits → offset 320..2367
            if reader.remaining() < 15 {
                return Err(DecompressError::TruncatedBitstream);
            }
            reader.read_bits(4)?;
            let payload = reader.read_bits(11)? as usize;
            return Ok(payload + 320);
        }

        // Check for '11110' or '11111' (5 bits)
        if reader.remaining() < 5 {
            return Err(DecompressError::TruncatedBitstream);
        }
        let top5 = reader.peek(5);
        if top5 == 0b11110 {
            // 11110 + 8 bits → offset 64..319
            if reader.remaining() < 13 {
                return Err(DecompressError::TruncatedBitstream);
            }
            reader.read_bits(5)?;
            let payload = reader.read_bits(8)? as usize;
            Ok(payload + 64)
        } else {
            // 11111 + 6 bits → offset 0..63
            if reader.remaining() < 11 {
                return Err(DecompressError::TruncatedBitstream);
            }
            reader.read_bits(5)?;
            let payload = reader.read_bits(6)? as usize;
            Ok(payload)
        }
    }
}

/// Decode length-of-match from bitstream.
///
/// Both 8K and 64K share the same encoding up to row 12 (L-o-M ≤ 8191).
/// The 64K variant adds rows 13–15 for L-o-M up to 65535.
///
/// MS-RDPBCGR §3.1.8.4.1.2.2 / §3.1.8.4.2.2.2:
///   `0`              → 3
///   `10` + 2 bits    → 4..7
///   `110` + 3 bits   → 8..15
///   `1110` + 4 bits  → 16..31
///   ...
///   `1111..10` + N bits → base..base+(2^N - 1)
fn decode_length_of_match<const HISTORY_SIZE: usize>(
    reader: &mut BitReader<'_>,
) -> Result<usize, DecompressError> {
    let max_rows = if HISTORY_SIZE == HISTORY_SIZE_8K { 12 } else { 15 };

    // Count leading 1-bits to determine the row
    let mut ones: u32 = 0;
    loop {
        if reader.remaining() < 1 {
            return Err(DecompressError::TruncatedBitstream);
        }
        let bit = reader.peek(1);
        if bit == 0 {
            // Consume the terminating 0 bit
            reader.read_bits(1)?;
            break;
        }
        reader.read_bits(1)?;
        ones += 1;
        if ones >= max_rows as u32 {
            // Last row has no terminating 0 bit; the row index is `ones`
            // Actually, looking at the table more carefully:
            // Row 0: '0' → L-o-M = 3 (ones=0)
            // Row 1: '10' + 2 bits → L-o-M = 4..7 (ones=1)
            // Row 2: '110' + 3 bits → L-o-M = 8..15 (ones=2)
            // ...
            // Row 11 (8K): '111111111110' + 12 bits → L-o-M = 4096..8191 (ones=11)
            // We should not exceed max_rows-1 ones before a 0.
            // If we do, it's a bitstream error. But actually the last valid row
            // for 8K is ones=11 (row 12 in 1-indexed), terminated by '0'.
            // There's no "unterminated" row in the spec.
            return Err(DecompressError::TruncatedBitstream);
        }
    }

    // ones=0 → L-o-M = 3, no extra bits
    if ones == 0 {
        return Ok(3);
    }

    // Row `ones`: read (ones+1) extra bits
    let extra_bits = ones + 1;
    if reader.remaining() < extra_bits {
        return Err(DecompressError::TruncatedBitstream);
    }
    let payload = reader.read_bits(extra_bits)? as usize;
    let base = 1usize << (ones + 1); // 2^(ones+1)
    Ok(base + payload)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::string::String;

    use super::*;

    // ── Helper: build a bitstream from a string of '0'/'1' chars ──

    fn bits_to_bytes(bits: &str) -> Vec<u8> {
        let bits: Vec<u8> = bits
            .chars()
            .filter(|c| *c == '0' || *c == '1')
            .map(|c| if c == '1' { 1 } else { 0 })
            .collect();
        let mut bytes = Vec::new();
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                byte |= bit << (7 - i);
            }
            bytes.push(byte);
        }
        bytes
    }

    // ── Literal encoding tests ──

    #[test]
    fn literal_below_0x80() {
        // 'A' = 0x41 = 0b1000001, encoded as: 0 1000001 (8 bits)
        let data = bits_to_bytes("01000001");
        let mut dec = Mppc8kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();
        assert_eq!(out, b"A");
    }

    #[test]
    fn literal_0x80() {
        // 0x80 encoded as: 10 0000000 (9 bits)
        let data = bits_to_bytes("100000000");
        let mut dec = Mppc8kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();
        assert_eq!(out, &[0x80]);
    }

    #[test]
    fn literal_0xff() {
        // 0xFF encoded as: 10 1111111 (9 bits)
        let data = bits_to_bytes("101111111");
        let mut dec = Mppc8kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();
        assert_eq!(out, &[0xFF]);
    }

    #[test]
    fn multiple_literals() {
        // "Hi" = 0x48 0x69
        // 'H' (0x48): 0 1001000
        // 'i' (0x69): 0 1101001
        let data = bits_to_bytes("01001000 01101001");
        let mut dec = Mppc8kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();
        assert_eq!(out, b"Hi");
    }

    // ── Copy-offset + length-of-match tests (8K) ──

    #[test]
    fn copy_token_8k_simple() {
        // Encode "abcabc":
        //   Literals 'a','b','c' then copy offset=3, lom=3
        //   'a' (0x61): 0 1100001
        //   'b' (0x62): 0 1100010
        //   'c' (0x63): 0 1100011
        //   copy_offset=3: 1111 000011 (8K: 1111 + 6-bit payload)
        //   lom=3: 0
        let data = bits_to_bytes("01100001 01100010 01100011 1111000011 0");
        let mut dec = Mppc8kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();
        assert_eq!(out, b"abcabc");
    }

    #[test]
    fn replicating_copy_overlap() {
        // "Xcdcdcd": 'X','c','d' then copy offset=2, lom=4
        // 'X' (0x58): 0 1011000
        // 'c' (0x63): 0 1100011
        // 'd' (0x64): 0 1100100
        // copy_offset=2: 1111 000010 (8K)
        // lom=4: 10 00 (row 1: '10' + 2 bits, value=4-4=0 → bits=00)
        let data = bits_to_bytes("01011000 01100011 01100100 1111000010 1000");
        let mut dec = Mppc8kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();
        assert_eq!(out, b"Xcdcdcd");
    }

    #[test]
    fn copy_offset_8k_range_64_319() {
        // offset=128: 1110 01000000 (8K: 1110 + 8 bits, payload = 128-64 = 64 = 0b01000000)
        // First write 128 literal 'A's, then copy offset=128, lom=3
        let mut bitstream = String::new();
        for _ in 0..128 {
            bitstream.push_str("01000001"); // 'A'
        }
        bitstream.push_str("1110 01000000"); // offset=128
        bitstream.push_str("0"); // lom=3

        let data = bits_to_bytes(&bitstream);
        let mut dec = Mppc8kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();
        assert_eq!(out.len(), 131);
        assert!(out.iter().all(|&b| b == b'A'));
    }

    #[test]
    fn copy_offset_8k_range_320_8191() {
        // offset=320: 110 + 13 bits (payload = 320-320 = 0)
        // Write 320 'B's, then copy offset=320, lom=3
        let mut bitstream = String::new();
        for _ in 0..320 {
            bitstream.push_str("01000010"); // 'B'
        }
        bitstream.push_str("110 0000000000000"); // offset=320
        bitstream.push_str("0"); // lom=3

        let data = bits_to_bytes(&bitstream);
        let mut dec = Mppc8kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();
        assert_eq!(out.len(), 323);
        assert!(out.iter().all(|&b| b == b'B'));
    }

    // ── Copy-offset tests (64K) ──

    #[test]
    fn copy_token_64k_simple() {
        // "abcabc" with 64K variant:
        //   copy_offset=3: 11111 000011 (64K: 11111 + 6-bit)
        //   lom=3: 0
        let data = bits_to_bytes("01100001 01100010 01100011 11111000011 0");
        let mut dec = Mppc64kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();
        assert_eq!(out, b"abcabc");
    }

    #[test]
    fn copy_offset_64k_range_64_319() {
        // offset=128: 11110 01000000 (64K: 11110 + 8 bits, payload = 128-64 = 64)
        let mut bitstream = String::new();
        for _ in 0..128 {
            bitstream.push_str("01000001"); // 'A'
        }
        bitstream.push_str("11110 01000000"); // offset=128
        bitstream.push_str("0"); // lom=3

        let data = bits_to_bytes(&bitstream);
        let mut dec = Mppc64kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();
        assert_eq!(out.len(), 131);
    }

    #[test]
    fn copy_offset_64k_range_320_2367() {
        // offset=320: 1110 + 11 bits (payload = 320-320 = 0)
        let mut bitstream = String::new();
        for _ in 0..320 {
            bitstream.push_str("01000010"); // 'B'
        }
        bitstream.push_str("1110 00000000000"); // offset=320
        bitstream.push_str("0"); // lom=3

        let data = bits_to_bytes(&bitstream);
        let mut dec = Mppc64kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();
        assert_eq!(out.len(), 323);
    }

    // ── Length-of-match tests ──

    #[test]
    fn lom_values() {
        // Test various L-o-M values by encoding them and decoding
        // Row 0: '0' → 3
        // Row 1: '10' + 2 bits → 4..7
        // Row 2: '110' + 3 bits → 8..15

        // Helper: build a packet with 4 literal 'A's then copy offset=4, lom=N
        fn test_lom(lom: usize) {
            let mut bitstream = String::new();
            // 4 literal 'A's
            for _ in 0..4 {
                bitstream.push_str("01000001");
            }
            // copy offset=4: 1111 000100 (8K)
            bitstream.push_str("1111 000100");
            // encode lom
            if lom == 3 {
                bitstream.push('0');
            } else {
                // Find the row: base = 2^(row+1), row such that base <= lom < 2*base
                let mut row = 0u32;
                loop {
                    let base = 1usize << (row + 2);
                    if lom < base {
                        break;
                    }
                    row += 1;
                }
                // row ones followed by '0'
                for _ in 0..row {
                    bitstream.push('1');
                }
                bitstream.push('0');
                // (row+1) payload bits
                let base = 1usize << (row + 1);
                let payload = lom - base;
                let nbits = row + 1;
                for i in (0..nbits).rev() {
                    bitstream.push(if (payload >> i) & 1 == 1 { '1' } else { '0' });
                }
            }

            let data = bits_to_bytes(&bitstream);
            let mut dec = Mppc8kDecompressor::new();
            let mut out = Vec::new();
            dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
                .unwrap();
            // Expected: 4 A's + lom copies of those A's (wrapping pattern "AAAA")
            assert_eq!(out.len(), 4 + lom, "lom={lom}");
            assert!(out.iter().all(|&b| b == b'A'), "lom={lom}");
        }

        test_lom(3);
        test_lom(4);
        test_lom(7);
        test_lom(8);
        test_lom(15);
        test_lom(16);
        test_lom(31);
        test_lom(32);
        test_lom(63);
        test_lom(64);
        test_lom(127);
        test_lom(128);
        test_lom(255);
        test_lom(256);
        test_lom(512);
        test_lom(1024);
        test_lom(2048);
        test_lom(4096);
    }

    #[test]
    fn lom_values_64k() {
        // Test L-o-M values specific to the 64K variant (rows 13-15)
        fn test_lom_64k(lom: usize) {
            let mut bitstream = String::new();
            // 4 literal 'A's
            for _ in 0..4 {
                bitstream.push_str("01000001");
            }
            // copy offset=4: 11111 000100 (64K: 11111 + 6-bit)
            bitstream.push_str("11111 000100");
            // encode lom
            if lom == 3 {
                bitstream.push('0');
            } else {
                let mut row = 0u32;
                loop {
                    let base = 1usize << (row + 2);
                    if lom < base {
                        break;
                    }
                    row += 1;
                }
                for _ in 0..row {
                    bitstream.push('1');
                }
                bitstream.push('0');
                let base = 1usize << (row + 1);
                let payload = lom - base;
                let nbits = row + 1;
                for i in (0..nbits).rev() {
                    bitstream.push(if (payload >> i) & 1 == 1 { '1' } else { '0' });
                }
            }

            let data = bits_to_bytes(&bitstream);
            let mut dec = Mppc64kDecompressor::new();
            let mut out = Vec::new();
            dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
                .unwrap();
            assert_eq!(out.len(), 4 + lom, "lom={lom}");
            assert!(out.iter().all(|&b| b == b'A'), "lom={lom}");
        }

        test_lom_64k(3);
        test_lom_64k(255);
        test_lom_64k(4096);
        test_lom_64k(8192);
        test_lom_64k(16384);
        test_lom_64k(32768);
    }

    // ── 64K copy-offset fourth range (2368..65535) ──

    #[test]
    fn copy_offset_64k_range_2368_65535() {
        // offset=2368: 110 + 16 bits (payload = 2368-2368 = 0)
        // Write 2368 'C's, then copy offset=2368, lom=3
        let mut bitstream = String::new();
        for _ in 0..2368 {
            bitstream.push_str("01000011"); // 'C'
        }
        bitstream.push_str("110 0000000000000000"); // offset=2368 (16-bit payload = 0)
        bitstream.push_str("0"); // lom=3

        let data = bits_to_bytes(&bitstream);
        let mut dec = Mppc64kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();
        assert_eq!(out.len(), 2371);
        assert!(out.iter().all(|&b| b == b'C'));
    }

    // ── Flag handling tests ──

    #[test]
    fn uncompressed_payload() {
        let mut dec = Mppc8kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(b"hello", PACKET_FLUSHED, &mut out).unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(&dec.history[..5], b"hello");
        assert_eq!(dec.offset, 5);
    }

    #[test]
    fn packet_flushed_resets_history() {
        let mut dec = Mppc8kDecompressor::new();
        let mut out = Vec::new();
        // Write some data
        dec.decompress(b"test", 0, &mut out).unwrap();
        assert_eq!(dec.offset, 4);

        // Flush: history should be zeroed, offset reset
        out.clear();
        dec.decompress(b"new", PACKET_FLUSHED, &mut out).unwrap();
        assert_eq!(dec.offset, 3);
        assert_eq!(out, b"new");
    }

    #[test]
    fn packet_at_front_preserves_content() {
        let mut dec = Mppc8kDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(b"ABCD", 0, &mut out).unwrap();
        assert_eq!(dec.offset, 4);

        // AT_FRONT: offset resets but content stays
        out.clear();
        dec.decompress(
            b"EF",
            PACKET_AT_FRONT,
            &mut out,
        )
        .unwrap();
        assert_eq!(dec.offset, 2);
        assert_eq!(&dec.history[..4], b"EFCD"); // first 2 bytes overwritten
        assert_eq!(out, b"EF");
    }

    #[test]
    fn history_overflow_returns_error() {
        let mut dec = Mppc8kDecompressor::new();
        let data = [0u8; HISTORY_SIZE_8K + 1];
        let mut out = Vec::new();
        let result = dec.decompress(&data, PACKET_FLUSHED, &mut out);
        assert_eq!(result, Err(DecompressError::HistoryOverflow));
    }

    // ── Sequential packet test ──

    #[test]
    fn sequential_packets_share_history() {
        let mut dec = Mppc8kDecompressor::new();
        let mut out = Vec::new();

        // Packet 1: uncompressed "abc"
        dec.decompress(b"abc", PACKET_FLUSHED, &mut out).unwrap();
        assert_eq!(out, b"abc");
        assert_eq!(dec.offset, 3);

        // Packet 2: compressed, references "abc" from packet 1
        // copy offset=3, lom=3 → "abc" again
        // 1111 000011 0
        let data = bits_to_bytes("1111000011 0");
        out.clear();
        dec.decompress(&data, PACKET_COMPRESSED, &mut out).unwrap();
        assert_eq!(out, b"abc");
        assert_eq!(dec.offset, 6);
    }
}
