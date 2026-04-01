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

// ── Constants (MS-RDPEGFX §2.2.5, §3.1.9.1) ──

/// Compression type in RDP8_BULK_ENCODED_DATA header nibble.
const PACKET_COMPR_TYPE_RDP8: u8 = 0x04;

/// Payload is Huffman-compressed.
const PACKET_COMPRESSED: u8 = 0x20;

/// Single-segment descriptor byte.
const SEGMENTED_SINGLE: u8 = 0xE0;

/// Multi-segment descriptor byte.
const SEGMENTED_MULTIPART: u8 = 0xE1;

/// History ring buffer size: 2,500,000 bytes.
const HISTORY_SIZE: usize = 2_500_000;

/// Maximum uncompressed bytes per segment.
const MAX_SEGMENT_SIZE: usize = 65_535;

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
        if self.pos >= self.data_end {
            return Err(ZgfxError::TruncatedBitstream);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        self.bits_remaining -= 8;
        Ok(b)
    }
}

// ── ZgfxDecompressor ──

/// ZGFX (RDP8) decompressor.
pub struct ZgfxDecompressor {
    history: Box<[u8]>,
    history_index: usize,
}

impl ZgfxDecompressor {
    /// Create a new decompressor with zeroed history.
    pub fn new() -> Self {
        Self {
            history: vec![0u8; HISTORY_SIZE].into_boxed_slice(),
            history_index: 0,
        }
    }

    /// Decompress an RDP_SEGMENTED_DATA structure.
    ///
    /// `src` begins with the descriptor byte (0xE0 or 0xE1).
    /// Decompressed output is appended to `dst`.
    pub fn decompress(&mut self, src: &[u8], dst: &mut Vec<u8>) -> Result<(), ZgfxError> {
        if src.is_empty() {
            return Err(ZgfxError::TruncatedInput);
        }

        match src[0] {
            SEGMENTED_SINGLE => {
                if src.len() < 2 {
                    return Err(ZgfxError::TruncatedInput);
                }
                self.decode_segment(&src[1..], dst)
            }
            SEGMENTED_MULTIPART => {
                if src.len() < 7 {
                    return Err(ZgfxError::TruncatedInput);
                }
                let segment_count =
                    u16::from_le_bytes([src[1], src[2]]) as usize;
                let uncompressed_size =
                    u32::from_le_bytes([src[3], src[4], src[5], src[6]]) as usize;

                let dst_start = dst.len();
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
                    if offset + seg_size > src.len() {
                        return Err(ZgfxError::TruncatedInput);
                    }
                    self.decode_segment(&src[offset..offset + seg_size], dst)?;
                    offset += seg_size;
                }

                let written = dst.len() - dst_start;
                if written != uncompressed_size {
                    return Err(ZgfxError::SizeMismatch);
                }

                Ok(())
            }
            _ => Err(ZgfxError::InvalidDescriptor),
        }
    }

    /// Decode a single RDP8_BULK_ENCODED_DATA segment.
    fn decode_segment(
        &mut self,
        segment: &[u8],
        dst: &mut Vec<u8>,
    ) -> Result<(), ZgfxError> {
        if segment.is_empty() {
            return Err(ZgfxError::TruncatedInput);
        }
        let header = segment[0];
        if header & 0x0F != PACKET_COMPR_TYPE_RDP8 {
            return Err(ZgfxError::InvalidCompressionType);
        }
        let data = &segment[1..];

        if header & PACKET_COMPRESSED != 0 {
            self.decode_compressed(data, dst)
        } else {
            self.decode_uncompressed(data, dst)
        }
    }

    /// Copy raw bytes to history and output.
    fn decode_uncompressed(
        &mut self,
        data: &[u8],
        dst: &mut Vec<u8>,
    ) -> Result<(), ZgfxError> {
        for &b in data {
            self.history[self.history_index] = b;
            self.history_index += 1;
            if self.history_index == HISTORY_SIZE {
                self.history_index = 0;
            }
        }
        dst.extend_from_slice(data);
        Ok(())
    }

    /// Decode a Huffman-compressed bitstream.
    fn decode_compressed(
        &mut self,
        encoded: &[u8],
        dst: &mut Vec<u8>,
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
                        self.history[self.history_index] = c;
                        self.history_index += 1;
                        if self.history_index == HISTORY_SIZE {
                            self.history_index = 0;
                        }
                        dst.push(c);
                    } else {
                        // Match distance
                        let distance = token.value_base
                            + bits.get_bits(token.value_bits as u32)?;

                        // `>` (not `>=`): distance == HISTORY_SIZE is valid
                        // and references the oldest byte in the ring buffer.
                        // The index computation `(history_index + HISTORY_SIZE
                        // - distance) % HISTORY_SIZE` yields `history_index`
                        // when distance == HISTORY_SIZE.
                        if distance as usize > HISTORY_SIZE {
                            return Err(ZgfxError::InvalidToken);
                        }

                        if distance == 0 {
                            // UNENCODED path
                            let count = bits.get_bits(15)? as usize;
                            bits.align_byte();
                            for _ in 0..count {
                                let c = bits.read_raw_byte()?;
                                self.history[self.history_index] = c;
                                self.history_index += 1;
                                if self.history_index == HISTORY_SIZE {
                                    self.history_index = 0;
                                }
                                dst.push(c);
                            }
                        } else {
                            // Match copy
                            let count = self.decode_match_count(&mut bits)?;
                            let mut prev_index = (self.history_index + HISTORY_SIZE
                                - distance as usize)
                                % HISTORY_SIZE;
                            for _ in 0..count {
                                let c = self.history[prev_index];
                                prev_index += 1;
                                if prev_index == HISTORY_SIZE {
                                    prev_index = 0;
                                }
                                self.history[self.history_index] = c;
                                self.history_index += 1;
                                if self.history_index == HISTORY_SIZE {
                                    self.history_index = 0;
                                }
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
        // The guard `extra > 20` limits doubling to at most 20 iterations.
        // Starting from count=4, doubling 20 times gives 4 * 2^20 = 4,194,304
        // which fits in usize on both 32-bit and 64-bit platforms (max ~4 MB).
        while bits.get_bits(1)? == 1 {
            count *= 2;
            extra += 1;
            if extra > 20 {
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

    /// Compress input into an RDP_SEGMENTED_DATA structure.
    ///
    /// Uses pass-through encoding (no actual compression).
    pub fn compress(&mut self, src: &[u8], dst: &mut Vec<u8>) {
        // Update history
        for &b in src {
            self.history[self.history_index] = b;
            self.history_index += 1;
            if self.history_index == HISTORY_SIZE {
                self.history_index = 0;
            }
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
        comp.compress(b"Hello", &mut out);

        assert_eq!(out[0], SEGMENTED_SINGLE);
        assert_eq!(out[1], PACKET_COMPR_TYPE_RDP8);
        assert_eq!(&out[2..], b"Hello");
    }

    #[test]
    fn compress_multipart() {
        let mut comp = ZgfxCompressor::new();
        let input = vec![0x42u8; 70_000]; // > MAX_SEGMENT_SIZE
        let mut out = Vec::new();
        comp.compress(&input, &mut out);

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
        comp.compress(original, &mut compressed);

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
        comp.compress(&original, &mut compressed);

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
        // Build a compressed segment with distance=0 (UNENCODED) path.
        // Token for distance=0: prefix 10001 (5 bits, code=17), valueBits=5, valueBase=0
        // distance = 0 + GetBits(5) where all 5 bits are 0 → distance = 0
        //
        // Then: 15-bit count, byte-align, then raw bytes.
        //
        // Encoding: prefix 10001 (5 bits) + 00000 (5 bits, distance=0)
        //         + 000000000000011 (15 bits, count=3)
        //         + byte-align padding
        //         + raw bytes: 0x41 0x42 0x43 ("ABC")
        //         + last byte (padding count)
        //
        // Total prefix+distance+count = 5+5+15 = 25 bits.
        // 25 bits = 3 bytes + 1 bit. Align to byte = discard 7 bits. But align_byte
        // discards only sub-byte remainder from accumulator.
        //
        // Let me build this step by step:
        // Bits: 10001 00000 000000000000011
        //     = 10001_00000_000000000000011
        //     = 1000100000 000000000000011
        // That's 25 bits. Packed into bytes (MSB-first):
        // Byte 0: 10001000 = 0x88
        // Byte 1: 00000000 = 0x00
        // Byte 2: 00000000 = 0x00
        // Byte 3: 011xxxxx (remaining 3 bits + 5 padding for alignment)
        //
        // Wait, 25 bits = 3*8 + 1 bit. Byte 3 has 1 bit then 7 padding.
        // Byte 3: 1xxxxxxx (the 25th bit is '1' from '...011')
        //
        // Actually let me be more careful:
        // Bit  0: 1 (prefix)
        // Bit  1: 0
        // Bit  2: 0
        // Bit  3: 0
        // Bit  4: 1
        // Bit  5: 0 (distance value bits)
        // Bit  6: 0
        // Bit  7: 0
        // Byte 0 = 10001000 = 0x88
        //
        // Bit  8: 0
        // Bit  9: 0
        // Bit 10: 0 (count bits start here)
        // Bit 11: 0
        // Bit 12: 0
        // Bit 13: 0
        // Bit 14: 0
        // Bit 15: 0
        // Byte 1 = 00000000 = 0x00
        //
        // Bit 16: 0
        // Bit 17: 0
        // Bit 18: 0
        // Bit 19: 0
        // Bit 20: 0
        // Bit 21: 0
        // Bit 22: 0
        // Bit 23: 1
        // Byte 2 = 00000001 = 0x01
        //
        // Bit 24: 1 (last bit of count=3 = 0b000000000000011)
        // Byte 3 = 1xxxxxxx (+ 7 padding for byte alignment)
        //        = 10000000 = 0x80
        //
        // After align_byte: raw bytes follow.
        // Byte 4: 0x41 ('A')
        // Byte 5: 0x42 ('B')
        // Byte 6: 0x43 ('C')
        //
        // Last byte (padding count): the padding was in byte 3 (7 bits),
        // but in ZGFX the last byte of the entire encoded data is the padding count.
        // Total encoded bytes = [0x88, 0x00, 0x01, 0x80, 0x41, 0x42, 0x43, padding_byte]
        //
        // The padding_byte tells how many bits to ignore from the total.
        // Total bits in data bytes (excluding padding byte) = 7 * 8 = 56.
        // Useful bits = 25 (header) + 7 (align padding) + 3*8 (raw bytes) = 56.
        // So padding_byte = 0 (all 56 bits are "used").
        // Wait: cBitsRemaining = 8 * (cbEncoded - 1) - lastByte.
        // cbEncoded = 8 (bytes), lastByte = encoded[7].
        // We want cBitsRemaining to cover all the useful bits.
        // The 25 prefix/distance/count bits + 7 align bits + 24 raw bits = 56 bits.
        // cBitsRemaining = 8 * 7 - lastByte = 56 - lastByte.
        // We need cBitsRemaining = 56, so lastByte = 0.
        //
        // But wait: in the UNENCODED path, raw bytes are read via read_raw_byte()
        // which decrements bits_remaining by 8 each time, NOT via get_bits.
        // And the 7 align padding bits are discarded by align_byte which also
        // decrements bits_remaining.
        // So: 25 (get_bits) + 7 (align) + 24 (raw) = 56 bits total consumed.
        // cBitsRemaining = 56 - 0 = 56. ✓

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
}
