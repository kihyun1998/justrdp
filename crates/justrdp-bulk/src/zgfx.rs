#![forbid(unsafe_code)]

//! ZGFX (RDP8) bulk compression and decompression.
//!
//! Implements the RDP 8.0 bulk compression algorithm described in:
//! - MS-RDPEGFX §2.2.5 (RDP_SEGMENTED_DATA, RDP8_BULK_ENCODED_DATA)
//! - MS-RDPEGFX §3.1.9.1.2 (Decompressing Data)
//! - MS-RDPEGFX §5 (Sample Code)

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::mppc::PACKET_COMPRESSED;

// ── Constants (MS-RDPEGFX §2.2.5, §3.1.9.1) ──

/// Compression type in RDP8_BULK_ENCODED_DATA header nibble (full ZGFX).
const PACKET_COMPR_TYPE_RDP8: u8 = 0x04;

/// Compression type for RDP8 Lite (DVC compressed data, MS-RDPEDYC 2.2.3).
const PACKET_COMPR_TYPE_RDP8_LITE: u8 = 0x06;

/// History ring buffer size for RDP8 Lite: 8,192 bytes.
const HISTORY_SIZE_LITE: usize = 8_192;

/// Single-segment descriptor byte.
const SEGMENTED_SINGLE: u8 = 0xE0;

/// Multi-segment descriptor byte.
const SEGMENTED_MULTIPART: u8 = 0xE1;

/// History ring buffer size: 2,500,000 bytes.
const HISTORY_SIZE: usize = 2_500_000;

/// Maximum uncompressed bytes per segment.
const MAX_SEGMENT_SIZE: usize = 65_535;

/// Maximum total decompressed output per `decompress()` call (64 MB).
///
/// This prevents memory exhaustion from crafted inputs: a multipart packet
/// can otherwise declare up to 4 GB via its `uncompressedSize` field.
const MAX_DECOMPRESSED_SIZE: usize = 64 * 1024 * 1024;

/// Maximum extra doublings in `decode_match_count` (limits match count to ~4 MB).
const MAX_MATCH_COUNT_EXTRA_BITS: u32 = 20;

/// Bit-width of the byte-count field in the UNENCODED token path (MS-RDPEGFX §3.1.9.1.2).
const UNENCODED_COUNT_BITS: u32 = 15;

// ── Error type ──

/// ZGFX decompression error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZgfxError {
    /// Input is too short.
    TruncatedInput,
    /// Bitstream ended mid-token.
    TruncatedBitstream,
    /// Invalid descriptor byte (not 0xE0 or 0xE1).
    InvalidDescriptor,
    /// Invalid compression type nibble in header.
    InvalidCompressionType,
    /// No token prefix matched in the Huffman table.
    InvalidToken,
    /// Multipart output size doesn't match declared uncompressedSize.
    SizeMismatch,
    /// Decompressed output exceeds `MAX_DECOMPRESSED_SIZE`.
    DecompressedSizeExceeded,
}

impl fmt::Display for ZgfxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedInput => write!(f, "ZGFX: truncated input"),
            Self::TruncatedBitstream => write!(f, "ZGFX: truncated bitstream"),
            Self::InvalidDescriptor => write!(f, "ZGFX: invalid descriptor byte"),
            Self::InvalidCompressionType => write!(f, "ZGFX: invalid compression type"),
            Self::InvalidToken => write!(f, "ZGFX: invalid token in bitstream"),
            Self::SizeMismatch => write!(f, "ZGFX: output size mismatch"),
            Self::DecompressedSizeExceeded => {
                write!(f, "ZGFX: decompressed output exceeds maximum size")
            }
        }
    }
}

// ── Static Huffman token table (MS-RDPEGFX §3.1.9.1.2, §5) ──

/// Token type: literal byte.
const TOKEN_LITERAL: u8 = 0;
/// Token type: match distance.
const TOKEN_MATCH: u8 = 1;

struct Token {
    prefix_length: u8,
    prefix_code: u32,
    value_bits: u8,
    token_type: u8,
    value_base: u32,
}

/// IMPORTANT: This table MUST be sorted by `(prefix_length, prefix_code)` in
/// ascending order. The `decode_compressed` loop does a linear scan,
/// accumulating prefix bits one at a time. Correct matching depends on shorter
/// prefixes being checked before longer ones, and within the same length,
/// codes being in ascending order so that accumulated bits are compared in the
/// right sequence. Reordering entries will produce silent wrong output.
#[rustfmt::skip]
static TOKEN_TABLE: &[Token] = &[
    Token { prefix_length: 1, prefix_code:   0, value_bits:  8, token_type: TOKEN_LITERAL, value_base:        0 },
    Token { prefix_length: 5, prefix_code:  17, value_bits:  5, token_type: TOKEN_MATCH,   value_base:        0 },
    Token { prefix_length: 5, prefix_code:  18, value_bits:  7, token_type: TOKEN_MATCH,   value_base:       32 },
    Token { prefix_length: 5, prefix_code:  19, value_bits:  9, token_type: TOKEN_MATCH,   value_base:      160 },
    Token { prefix_length: 5, prefix_code:  20, value_bits: 10, token_type: TOKEN_MATCH,   value_base:      672 },
    Token { prefix_length: 5, prefix_code:  21, value_bits: 12, token_type: TOKEN_MATCH,   value_base:     1696 },
    Token { prefix_length: 5, prefix_code:  24, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x00 },
    Token { prefix_length: 5, prefix_code:  25, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x01 },
    Token { prefix_length: 6, prefix_code:  44, value_bits: 14, token_type: TOKEN_MATCH,   value_base:     5792 },
    Token { prefix_length: 6, prefix_code:  45, value_bits: 15, token_type: TOKEN_MATCH,   value_base:    22176 },
    Token { prefix_length: 6, prefix_code:  52, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x02 },
    Token { prefix_length: 6, prefix_code:  53, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x03 },
    Token { prefix_length: 6, prefix_code:  54, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0xFF },
    Token { prefix_length: 7, prefix_code:  92, value_bits: 18, token_type: TOKEN_MATCH,   value_base:    54944 },
    Token { prefix_length: 7, prefix_code:  93, value_bits: 20, token_type: TOKEN_MATCH,   value_base:   317088 },
    Token { prefix_length: 7, prefix_code: 110, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x04 },
    Token { prefix_length: 7, prefix_code: 111, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x05 },
    Token { prefix_length: 7, prefix_code: 112, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x06 },
    Token { prefix_length: 7, prefix_code: 113, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x07 },
    Token { prefix_length: 7, prefix_code: 114, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x08 },
    Token { prefix_length: 7, prefix_code: 115, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x09 },
    Token { prefix_length: 7, prefix_code: 116, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x0A },
    Token { prefix_length: 7, prefix_code: 117, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x0B },
    Token { prefix_length: 7, prefix_code: 118, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x3A },
    Token { prefix_length: 7, prefix_code: 119, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x3B },
    Token { prefix_length: 7, prefix_code: 120, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x3C },
    Token { prefix_length: 7, prefix_code: 121, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x3D },
    Token { prefix_length: 7, prefix_code: 122, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x3E },
    Token { prefix_length: 7, prefix_code: 123, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x3F },
    Token { prefix_length: 7, prefix_code: 124, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x40 },
    Token { prefix_length: 7, prefix_code: 125, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x80 },
    Token { prefix_length: 8, prefix_code: 188, value_bits: 20, token_type: TOKEN_MATCH,   value_base:  1365664 },
    Token { prefix_length: 8, prefix_code: 189, value_bits: 21, token_type: TOKEN_MATCH,   value_base:  2414240 },
    Token { prefix_length: 8, prefix_code: 252, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x0C },
    Token { prefix_length: 8, prefix_code: 253, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x38 },
    Token { prefix_length: 8, prefix_code: 254, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x39 },
    Token { prefix_length: 8, prefix_code: 255, value_bits:  0, token_type: TOKEN_LITERAL, value_base:     0x66 },
    Token { prefix_length: 9, prefix_code: 380, value_bits: 22, token_type: TOKEN_MATCH,   value_base:  4511392 },
    Token { prefix_length: 9, prefix_code: 381, value_bits: 23, token_type: TOKEN_MATCH,   value_base:  8705696 },
    Token { prefix_length: 9, prefix_code: 382, value_bits: 24, token_type: TOKEN_MATCH,   value_base: 17094304 },
];

// ── ZGFX bitstream reader ──

/// MSB-first bitstream reader for ZGFX.
///
/// The last byte of the encoded data stores the number of padding bits
/// to ignore, NOT data. `bits_remaining` tracks the total useful bits.
struct ZgfxBits<'a> {
    data: &'a [u8],
    /// Points to the byte AFTER the last data byte (the padding-count byte).
    data_end: usize,
    pos: usize,
    acc: u32,
    acc_bits: u32,
    bits_remaining: i64,
}

impl<'a> ZgfxBits<'a> {
    fn new(encoded: &'a [u8]) -> Result<Self, ZgfxError> {
        if encoded.is_empty() {
            return Err(ZgfxError::TruncatedInput);
        }
        let last_byte = encoded[encoded.len() - 1] as i64;
        let total_bits = 8 * (encoded.len() as i64 - 1) - last_byte;
        if total_bits < 0 {
            return Err(ZgfxError::TruncatedBitstream);
        }
        Ok(Self {
            data: encoded,
            data_end: encoded.len() - 1,
            pos: 0,
            acc: 0,
            acc_bits: 0,
            bits_remaining: total_bits,
        })
    }

    fn fill(&mut self) {
        while self.acc_bits <= 24 && self.pos < self.data_end {
            self.acc = (self.acc << 8) | self.data[self.pos] as u32;
            self.acc_bits += 8;
            self.pos += 1;
        }
    }

    fn get_bits(&mut self, n: u32) -> Result<u32, ZgfxError> {
        if (n as i64) > self.bits_remaining {
            return Err(ZgfxError::TruncatedBitstream);
        }
        self.fill();
        if self.acc_bits < n {
            return Err(ZgfxError::TruncatedBitstream);
        }
        self.acc_bits -= n;
        self.bits_remaining -= n as i64;
        let val = (self.acc >> self.acc_bits) & ((1 << n) - 1);
        Ok(val)
    }

    fn has_bits(&self) -> bool {
        self.bits_remaining > 0
    }

    /// Discard remaining bits in the accumulator and rewind any
    /// pre-loaded bytes so `read_raw_byte()` starts at the correct
    /// byte boundary (for UNENCODED path).
    fn align_byte(&mut self) {
        // Rewind pre-loaded full bytes back to the input stream.
        // Safety: `fill()` increments `pos` for each byte loaded into the
        // accumulator, so `pos >= full_bytes_in_acc` is always true here.
        let full_bytes_in_acc = self.acc_bits / 8;
        if full_bytes_in_acc > 0 {
            assert!(
                self.pos >= full_bytes_in_acc as usize,
                "align_byte: pos ({}) < full_bytes_in_acc ({})",
                self.pos,
                full_bytes_in_acc,
            );
            self.pos -= full_bytes_in_acc as usize;
        }
        // Discard only the sub-byte remainder
        let remainder = self.acc_bits % 8;
        if remainder > 0 {
            self.bits_remaining -= remainder as i64;
        }
        self.acc_bits = 0;
        self.acc = 0;
    }

    /// Read one raw byte from the input (for UNENCODED path).
    fn read_raw_byte(&mut self) -> Result<u8, ZgfxError> {
        if self.bits_remaining < 8 {
            return Err(ZgfxError::TruncatedBitstream);
        }
        if self.pos >= self.data_end {
            return Err(ZgfxError::TruncatedBitstream);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        self.bits_remaining -= 8;
        Ok(b)
    }
}

// ── Shared ring-buffer write ──

/// Write one byte to a ring buffer at `*index`, wrapping when it reaches
/// the end of `history`. Used by both compressor and decompressor.
#[inline]
fn ring_write(history: &mut [u8], index: &mut usize, b: u8) {
    history[*index] = b;
    *index += 1;
    if *index == history.len() {
        *index = 0;
    }
}

// ── ZgfxDecompressor ──

/// ZGFX (RDP8) decompressor.
///
/// Supports both full RDP8 (ZGFX, 2.5 MB history) and RDP8 Lite
/// (DVC compressed data, 8 KB history).
pub struct ZgfxDecompressor {
    history: Box<[u8]>,
    history_index: usize,
    /// Accepted compression type nibble (0x04 for full, 0x06 for lite).
    compr_type: u8,
}

impl ZgfxDecompressor {
    /// Create a new full ZGFX decompressor (2.5 MB history, type 0x04).
    pub fn new() -> Self {
        Self {
            history: vec![0u8; HISTORY_SIZE].into_boxed_slice(),
            history_index: 0,
            compr_type: PACKET_COMPR_TYPE_RDP8,
        }
    }

    /// Create a new RDP8 Lite decompressor (8 KB history, type 0x06).
    ///
    /// Used for DVC compressed data (MS-RDPEDYC 2.2.3.3/2.2.3.4).
    pub fn new_lite() -> Self {
        Self {
            history: vec![0u8; HISTORY_SIZE_LITE].into_boxed_slice(),
            history_index: 0,
            compr_type: PACKET_COMPR_TYPE_RDP8_LITE,
        }
    }

    /// Reset the decompressor state without reallocating the history buffer.
    pub fn reset(&mut self) {
        self.history.fill(0);
        self.history_index = 0;
    }

    /// Decompress an RDP_SEGMENTED_DATA structure.
    ///
    /// `src` begins with the descriptor byte (0xE0 or 0xE1).
    /// Decompressed output is appended to `dst`.
    pub fn decompress(&mut self, src: &[u8], dst: &mut Vec<u8>) -> Result<(), ZgfxError> {
        if src.is_empty() {
            return Err(ZgfxError::TruncatedInput);
        }

        let dst_start = dst.len();
        // The output budget is shared across all segments (single or multi).
        // `decode_segment` and its callees check `dst.len() - dst_start`
        // against `MAX_DECOMPRESSED_SIZE` after every write.
        let output_limit = dst_start
            .checked_add(MAX_DECOMPRESSED_SIZE)
            .ok_or(ZgfxError::DecompressedSizeExceeded)?;

        match src[0] {
            SEGMENTED_SINGLE => {
                if src.len() < 2 {
                    return Err(ZgfxError::TruncatedInput);
                }
                self.decode_segment(&src[1..], dst, output_limit)?;
            }
            SEGMENTED_MULTIPART => {
                if src.len() < 7 {
                    return Err(ZgfxError::TruncatedInput);
                }
                let segment_count =
                    u16::from_le_bytes([src[1], src[2]]) as usize;
                let uncompressed_size =
                    u32::from_le_bytes([src[3], src[4], src[5], src[6]]) as usize;

                // Reject unreasonably large declared sizes upfront.
                if uncompressed_size > MAX_DECOMPRESSED_SIZE {
                    return Err(ZgfxError::DecompressedSizeExceeded);
                }

                let mut offset = 7;
                for _ in 0..segment_count {
                    if offset + 4 > src.len() {
                        return Err(ZgfxError::TruncatedInput);
                    }
                    let seg_size = u32::from_le_bytes([
                        src[offset],
                        src[offset + 1],
                        src[offset + 2],
                        src[offset + 3],
                    ]) as usize;
                    offset += 4;
                    let seg_end = offset
                        .checked_add(seg_size)
                        .ok_or(ZgfxError::TruncatedInput)?;
                    if seg_end > src.len() {
                        return Err(ZgfxError::TruncatedInput);
                    }
                    self.decode_segment(
                        &src[offset..seg_end],
                        dst,
                        output_limit,
                    )?;
                    offset = seg_end;
                }

                let written = dst.len() - dst_start;
                if written != uncompressed_size {
                    return Err(ZgfxError::SizeMismatch);
                }
            }
            _ => return Err(ZgfxError::InvalidDescriptor),
        }

        Ok(())
    }

    /// Write one byte to the ring-buffer history.
    #[inline]
    fn write_history(&mut self, b: u8) {
        ring_write(&mut self.history, &mut self.history_index, b);
    }

    /// Decode a single RDP8_BULK_ENCODED_DATA segment.
    ///
    /// `output_limit` is the absolute maximum `dst.len()` allowed; exceeding
    /// it returns `DecompressedSizeExceeded`.
    fn decode_segment(
        &mut self,
        segment: &[u8],
        dst: &mut Vec<u8>,
        output_limit: usize,
    ) -> Result<(), ZgfxError> {
        if segment.is_empty() {
            return Err(ZgfxError::TruncatedInput);
        }
        let header = segment[0];
        if header & 0x0F != self.compr_type {
            return Err(ZgfxError::InvalidCompressionType);
        }
        let data = &segment[1..];

        if header & PACKET_COMPRESSED != 0 {
            self.decode_compressed(data, dst, output_limit)
        } else {
            self.decode_uncompressed(data, dst, output_limit)
        }
    }

    /// Copy raw bytes to history and output.
    fn decode_uncompressed(
        &mut self,
        data: &[u8],
        dst: &mut Vec<u8>,
        output_limit: usize,
    ) -> Result<(), ZgfxError> {
        if dst.len().saturating_add(data.len()) > output_limit {
            return Err(ZgfxError::DecompressedSizeExceeded);
        }
        for &b in data {
            self.write_history(b);
        }
        dst.extend_from_slice(data);
        Ok(())
    }

    /// Decode a Huffman-compressed bitstream.
    fn decode_compressed(
        &mut self,
        encoded: &[u8],
        dst: &mut Vec<u8>,
        output_limit: usize,
    ) -> Result<(), ZgfxError> {
        let mut bits = ZgfxBits::new(encoded)?;

        while bits.has_bits() {
            // Scan token table, accumulating prefix bits
            let mut have_bits: u32 = 0;
            let mut in_prefix: u32 = 0;
            let mut matched = false;

            for token in TOKEN_TABLE {
                while have_bits < token.prefix_length as u32 {
                    if !bits.has_bits() {
                        return Ok(()); // end of stream mid-prefix
                    }
                    in_prefix = (in_prefix << 1) | bits.get_bits(1)?;
                    have_bits += 1;
                }

                if in_prefix == token.prefix_code {
                    if token.token_type == TOKEN_LITERAL {
                        // Literal byte
                        let c = if token.value_bits > 0 {
                            (token.value_base + bits.get_bits(token.value_bits as u32)?) as u8
                        } else {
                            token.value_base as u8
                        };
                        if dst.len() >= output_limit {
                            return Err(ZgfxError::DecompressedSizeExceeded);
                        }
                        self.write_history(c);
                        dst.push(c);
                    } else {
                        // Match distance
                        let distance = token.value_base
                            + bits.get_bits(token.value_bits as u32)?;

                        // `>` (not `>=`): distance == HISTORY_SIZE is valid
                        // and references the oldest byte in the ring buffer.
                        // distance == history.len() references the oldest byte in the ring.
        if distance as usize > self.history.len() {
                            return Err(ZgfxError::InvalidToken);
                        }

                        if distance == 0 {
                            // UNENCODED path (MS-RDPEGFX §3.1.9.1.2)
                            let count = bits.get_bits(UNENCODED_COUNT_BITS)? as usize;
                            bits.align_byte();
                            for _ in 0..count {
                                if dst.len() >= output_limit {
                                    return Err(ZgfxError::DecompressedSizeExceeded);
                                }
                                let c = bits.read_raw_byte()?;
                                self.write_history(c);
                                dst.push(c);
                            }
                        } else {
                            // Match copy
                            let count = self.decode_match_count(&mut bits)?;
                            if dst.len().saturating_add(count) > output_limit {
                                return Err(ZgfxError::DecompressedSizeExceeded);
                            }
                            let hist_size = self.history.len();
                            let mut prev_index = (self.history_index + hist_size
                                - distance as usize)
                                % hist_size;
                            for _ in 0..count {
                                let c = self.history[prev_index];
                                prev_index += 1;
                                if prev_index == hist_size {
                                    prev_index = 0;
                                }
                                self.write_history(c);
                                dst.push(c);
                            }
                        }
                    }
                    matched = true;
                    break;
                }
            }

            if !matched {
                return Err(ZgfxError::InvalidToken);
            }
        }

        Ok(())
    }

    /// Decode variable-length match count.
    ///
    /// - Bit 0 → count = 3
    /// - Bit 1, then doubling loop:
    ///   count=4, extra=2; while bit==1: count*=2, extra+=1; count += GetBits(extra)
    fn decode_match_count(&self, bits: &mut ZgfxBits<'_>) -> Result<usize, ZgfxError> {
        if bits.get_bits(1)? == 0 {
            return Ok(3);
        }
        let mut count: usize = 4;
        let mut extra: u32 = 2;
        // The guard limits doubling to at most 19 iterations (extra starts
        // at 2, fires at extra > 20). Max count from doubling alone is
        // 4 * 2^19 = 2,097,152 (~2 MB), fitting in usize on all platforms.
        while bits.get_bits(1)? == 1 {
            count *= 2;
            extra += 1;
            if extra > MAX_MATCH_COUNT_EXTRA_BITS {
                return Err(ZgfxError::TruncatedBitstream);
            }
        }
        count += bits.get_bits(extra)? as usize;
        Ok(count)
    }
}

impl Default for ZgfxDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ZgfxDecompressor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZgfxDecompressor")
            .field("history_index", &self.history_index)
            .finish()
    }
}

// ── ZgfxCompressor (minimal pass-through) ──

/// ZGFX (RDP8) compressor.
///
/// Currently implements pass-through encoding only (no LZ77 matching).
/// The output is valid ZGFX but uncompressed.
pub struct ZgfxCompressor {
    history: Box<[u8]>,
    history_index: usize,
}

impl ZgfxCompressor {
    /// Create a new compressor.
    pub fn new() -> Self {
        Self {
            history: vec![0u8; HISTORY_SIZE].into_boxed_slice(),
            history_index: 0,
        }
    }

    /// Write one byte to the ring-buffer history.
    #[inline]
    fn write_history(&mut self, b: u8) {
        ring_write(&mut self.history, &mut self.history_index, b);
    }

    /// Compress input into an RDP_SEGMENTED_DATA structure.
    ///
    /// Uses pass-through encoding (no actual compression).
    /// Returns an error if `src` is too large for the multipart header fields.
    pub fn compress(&mut self, src: &[u8], dst: &mut Vec<u8>) -> Result<(), ZgfxError> {
        // Reject inputs that would overflow the u32 uncompressedSize field
        // in the multipart header.
        if src.len() > u32::MAX as usize {
            return Err(ZgfxError::DecompressedSizeExceeded);
        }

        // Update history
        for &b in src {
            self.write_history(b);
        }

        if src.len() <= MAX_SEGMENT_SIZE {
            // Single segment
            dst.push(SEGMENTED_SINGLE);
            dst.push(PACKET_COMPR_TYPE_RDP8); // header: not compressed
            dst.extend_from_slice(src);
        } else {
            // Multi segment
            dst.push(SEGMENTED_MULTIPART);
            let segment_count = (src.len() + MAX_SEGMENT_SIZE - 1) / MAX_SEGMENT_SIZE;
            if segment_count > u16::MAX as usize {
                return Err(ZgfxError::DecompressedSizeExceeded);
            }
            dst.extend_from_slice(&(segment_count as u16).to_le_bytes());
            dst.extend_from_slice(&(src.len() as u32).to_le_bytes());

            let mut offset = 0;
            while offset < src.len() {
                let chunk_len = (src.len() - offset).min(MAX_SEGMENT_SIZE);
                let seg_size = (chunk_len + 1) as u32; // +1 for header byte
                dst.extend_from_slice(&seg_size.to_le_bytes());
                dst.push(PACKET_COMPR_TYPE_RDP8); // header: not compressed
                dst.extend_from_slice(&src[offset..offset + chunk_len]);
                offset += chunk_len;
            }
        }

        Ok(())
    }
}

impl Default for ZgfxCompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ZgfxCompressor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZgfxCompressor")
            .field("history_index", &self.history_index)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Decompressor tests ──

    #[test]
    fn single_segment_uncompressed() {
        // SEGMENTED_SINGLE + uncompressed "Hello"
        let input: &[u8] = &[
            0xE0, // SEGMENTED_SINGLE
            0x04, // header: COMPR_TYPE_RDP8, not compressed
            0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
        ];
        let mut dec = ZgfxDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(input, &mut out).unwrap();
        assert_eq!(out, b"Hello");
        assert_eq!(dec.history_index, 5);
        assert_eq!(&dec.history[..5], b"Hello");
    }

    #[test]
    fn single_segment_compressed_literal() {
        // Encode literal 'H' (0x48 = 0b01001000) using prefix '0' + 8-bit value.
        // Bits: 0 01001000 = 9 bits total.
        // Packed MSB-first into bytes:
        //   Byte 0: 00100100 = 0x24
        //   Byte 1: 0_______ (9th bit '0' + 7 padding bits) = 0x00
        // Last byte (padding count) = 7
        // Encoded data = [0x24, 0x00, 0x07]
        let input: &[u8] = &[
            0xE0, // SEGMENTED_SINGLE
            0x24, // header: COMPR_TYPE_RDP8 | PACKET_COMPRESSED
            0x24, // data byte 0
            0x00, // data byte 1 (9th bit + padding)
            0x07, // last byte: 7 padding bits
        ];
        let mut dec = ZgfxDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(input, &mut out).unwrap();
        assert_eq!(out, &[0x48]);
    }

    #[test]
    fn multipart_uncompressed() {
        // Build a multipart packet with 2 uncompressed segments
        let seg1_data = b"Hello";
        let seg2_data = b"World";

        let mut input = Vec::new();
        input.push(SEGMENTED_MULTIPART);
        input.extend_from_slice(&2u16.to_le_bytes()); // segmentCount
        input.extend_from_slice(&10u32.to_le_bytes()); // uncompressedSize

        // Segment 1
        let seg1_size = (seg1_data.len() + 1) as u32; // +1 for header
        input.extend_from_slice(&seg1_size.to_le_bytes());
        input.push(PACKET_COMPR_TYPE_RDP8); // header
        input.extend_from_slice(seg1_data);

        // Segment 2
        let seg2_size = (seg2_data.len() + 1) as u32;
        input.extend_from_slice(&seg2_size.to_le_bytes());
        input.push(PACKET_COMPR_TYPE_RDP8);
        input.extend_from_slice(seg2_data);

        let mut dec = ZgfxDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&input, &mut out).unwrap();
        assert_eq!(out, b"HelloWorld");
    }

    #[test]
    fn invalid_descriptor() {
        let mut dec = ZgfxDecompressor::new();
        let mut out = Vec::new();
        let result = dec.decompress(&[0xE2, 0x04], &mut out);
        assert_eq!(result, Err(ZgfxError::InvalidDescriptor));
    }

    #[test]
    fn invalid_compression_type() {
        let mut dec = ZgfxDecompressor::new();
        let mut out = Vec::new();
        let result = dec.decompress(&[0xE0, 0x01], &mut out); // type 0x01 = MPPC
        assert_eq!(result, Err(ZgfxError::InvalidCompressionType));
    }

    #[test]
    fn truncated_input() {
        let mut dec = ZgfxDecompressor::new();
        let mut out = Vec::new();
        assert_eq!(
            dec.decompress(&[], &mut out),
            Err(ZgfxError::TruncatedInput)
        );
        assert_eq!(
            dec.decompress(&[0xE0], &mut out),
            Err(ZgfxError::TruncatedInput)
        );
    }

    #[test]
    fn history_persists_across_segments() {
        // Two segments: first writes "AB", second references history
        let mut dec = ZgfxDecompressor::new();

        // Segment 1: uncompressed "AB"
        let seg1: &[u8] = &[0xE0, 0x04, 0x41, 0x42];
        let mut out = Vec::new();
        dec.decompress(seg1, &mut out).unwrap();
        assert_eq!(out, b"AB");
        assert_eq!(dec.history_index, 2);

        // Verify history is preserved for next call
        assert_eq!(&dec.history[..2], b"AB");
    }

    // ── Compressor tests ──

    #[test]
    fn compress_single_segment() {
        let mut comp = ZgfxCompressor::new();
        let mut out = Vec::new();
        comp.compress(b"Hello", &mut out).unwrap();

        assert_eq!(out[0], SEGMENTED_SINGLE);
        assert_eq!(out[1], PACKET_COMPR_TYPE_RDP8);
        assert_eq!(&out[2..], b"Hello");
    }

    #[test]
    fn compress_multipart() {
        let mut comp = ZgfxCompressor::new();
        let input = vec![0x42u8; 70_000]; // > MAX_SEGMENT_SIZE
        let mut out = Vec::new();
        comp.compress(&input, &mut out).unwrap();

        assert_eq!(out[0], SEGMENTED_MULTIPART);
        let seg_count = u16::from_le_bytes([out[1], out[2]]);
        assert_eq!(seg_count, 2);
        let uncomp_size = u32::from_le_bytes([out[3], out[4], out[5], out[6]]);
        assert_eq!(uncomp_size, 70_000);
    }

    // ── Roundtrip test ──

    #[test]
    fn roundtrip_single() {
        let original = b"Hello, ZGFX roundtrip test!";
        let mut comp = ZgfxCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(original, &mut compressed).unwrap();

        let mut dec = ZgfxDecompressor::new();
        let mut decompressed = Vec::new();
        dec.decompress(&compressed, &mut decompressed).unwrap();

        assert_eq!(decompressed, original);
    }

    #[test]
    fn roundtrip_multipart() {
        let original: Vec<u8> = (0..70_000).map(|i| (i % 256) as u8).collect();
        let mut comp = ZgfxCompressor::new();
        let mut compressed = Vec::new();
        comp.compress(&original, &mut compressed).unwrap();

        let mut dec = ZgfxDecompressor::new();
        let mut decompressed = Vec::new();
        dec.decompress(&compressed, &mut decompressed).unwrap();

        assert_eq!(decompressed, original);
    }

    #[test]
    fn multipart_size_mismatch() {
        // Build a multipart packet with wrong uncompressedSize
        let mut input = Vec::new();
        input.push(SEGMENTED_MULTIPART);
        input.extend_from_slice(&1u16.to_le_bytes()); // segmentCount = 1
        input.extend_from_slice(&999u32.to_le_bytes()); // wrong uncompressedSize

        let seg_data = b"AB";
        let seg_size = (seg_data.len() + 1) as u32;
        input.extend_from_slice(&seg_size.to_le_bytes());
        input.push(PACKET_COMPR_TYPE_RDP8);
        input.extend_from_slice(seg_data);

        let mut dec = ZgfxDecompressor::new();
        let mut out = Vec::new();
        let result = dec.decompress(&input, &mut out);
        assert_eq!(result, Err(ZgfxError::SizeMismatch));
    }

    #[test]
    fn compressed_unencoded_path() {
        // UNENCODED token: distance=0, count=3, raw bytes "ABC".
        //
        // Bit layout (MSB-first):
        //   prefix 10001 (5 bits, code=17) + distance 00000 (5 bits) = 0
        //   count 000000000000011 (15 bits) = 3
        //   byte-align (7 padding bits)
        //   raw: 0x41 0x42 0x43
        //
        // Packed bytes: [0x88, 0x00, 0x01, 0x80, 0x41, 0x42, 0x43]
        // Last byte = 0x00 (padding count: all 56 data bits are useful)

        let encoded: &[u8] = &[0x88, 0x00, 0x01, 0x80, 0x41, 0x42, 0x43, 0x00];
        let input: &[u8] = &{
            let mut v = Vec::new();
            v.push(SEGMENTED_SINGLE);
            v.push(PACKET_COMPR_TYPE_RDP8 | PACKET_COMPRESSED); // header
            v.extend_from_slice(encoded);
            v
        };

        let mut dec = ZgfxDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(input, &mut out).unwrap();
        assert_eq!(out, b"ABC");
    }

    #[test]
    fn truncated_bitstream_bad_padding() {
        // Compressed segment where last byte claims more padding than available
        // encoded = [0x00, 0xFF] → cBitsRemaining = 8*(2-1) - 255 = 8 - 255 < 0
        let input: &[u8] = &[
            0xE0,
            PACKET_COMPR_TYPE_RDP8 | PACKET_COMPRESSED,
            0x00, 0xFF,
        ];
        let mut dec = ZgfxDecompressor::new();
        let mut out = Vec::new();
        let result = dec.decompress(input, &mut out);
        assert_eq!(result, Err(ZgfxError::TruncatedBitstream));
    }

    // ── RDP8 Lite (new_lite) tests ──

    #[test]
    fn lite_uncompressed_roundtrip() {
        // SEGMENTED_SINGLE + RDP8 Lite header (type 0x06, not compressed) + data
        let input: &[u8] = &[
            0xE0, // SEGMENTED_SINGLE
            0x06, // PACKET_COMPR_TYPE_RDP8_LITE, not compressed
            0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
        ];
        let mut dec = ZgfxDecompressor::new_lite();
        let mut out = Vec::new();
        dec.decompress(input, &mut out).unwrap();
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn lite_rejects_full_compr_type() {
        // Lite decompressor should reject type 0x04 (full RDP8)
        let input: &[u8] = &[
            0xE0,
            0x04, // PACKET_COMPR_TYPE_RDP8 — wrong for Lite
            0x48, 0x65,
        ];
        let mut dec = ZgfxDecompressor::new_lite();
        let mut out = Vec::new();
        assert_eq!(
            dec.decompress(input, &mut out),
            Err(ZgfxError::InvalidCompressionType)
        );
    }

    #[test]
    fn full_rejects_lite_compr_type() {
        // Full decompressor should reject type 0x06 (Lite)
        let input: &[u8] = &[
            0xE0,
            0x06, // PACKET_COMPR_TYPE_RDP8_LITE — wrong for full
            0x48, 0x65,
        ];
        let mut dec = ZgfxDecompressor::new();
        let mut out = Vec::new();
        assert_eq!(
            dec.decompress(input, &mut out),
            Err(ZgfxError::InvalidCompressionType)
        );
    }

    #[test]
    fn lite_history_size() {
        let dec = ZgfxDecompressor::new_lite();
        assert_eq!(dec.history.len(), 8_192);
    }

    #[test]
    fn reset_preserves_mode() {
        let mut dec = ZgfxDecompressor::new_lite();
        // Write some data
        let input: &[u8] = &[0xE0, 0x06, 0x41, 0x42, 0x43];
        let mut out = Vec::new();
        dec.decompress(input, &mut out).unwrap();
        assert_eq!(dec.history_index, 3);

        dec.reset();
        assert_eq!(dec.history_index, 0);
        assert_eq!(dec.history.len(), 8_192); // still Lite
        assert_eq!(dec.compr_type, PACKET_COMPR_TYPE_RDP8_LITE);
    }
}
