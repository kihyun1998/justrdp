#![forbid(unsafe_code)]

//! NCRUSH bulk decompression (RDP 6.0).
//!
//! Implements the decompression algorithm described in:
//! - MS-RDPEGDI §3.1.8.1 (RDP 6.0 Bulk Compression)
//! - MS-RDPBCGR §2.2.8.1.1.1.2 (PACKET_COMPR_TYPE_RDP6 = 0x2)

use alloc::vec::Vec;

use crate::mppc::{BitReader, DecompressError, PACKET_AT_FRONT, PACKET_COMPRESSED, PACKET_FLUSHED};

// ── Constants ──

/// RDP 6.0 NCRUSH compression type (MS-RDPBCGR §2.2.8.1.1.1.2).
pub const PACKET_COMPR_TYPE_RDP6: u8 = 0x2;

const HISTORY_SIZE: usize = 65_536;
const HISTORY_MASK: usize = HISTORY_SIZE - 1;

/// Number of LEC (Literal/EOS/CopyOffset) symbols.
const NUM_LEC_SYMBOLS: usize = 294;
/// Number of LOM (Length-of-Match) symbols.
const NUM_LOM_SYMBOLS: usize = 32;
/// Maximum LEC Huffman code bit-length.
const MAX_LEC_BITS: u32 = 13;
/// Maximum LOM Huffman code bit-length.
const MAX_LOM_BITS: u32 = 9;
/// LEC flat lookup table size (2^13).
const LEC_TABLE_SIZE: usize = 1 << MAX_LEC_BITS; // 8192
/// LOM flat lookup table size (2^9).
const LOM_TABLE_SIZE: usize = 1 << MAX_LOM_BITS; // 512

/// Number of entries in the offset cache.
const OFFSET_CACHE_SIZE: usize = 4;
/// Number of entries in the LOM base/bits LUTs.
const NUM_LOM_LUT: usize = 30;

// ── Static Huffman bit-length tables (MS-RDPEGDI §3.1.8.1.4.1) ──

/// Bit-lengths for 294 LEC Huffman codes.
#[rustfmt::skip]
const HUFF_LEN_LEC: [u8; NUM_LEC_SYMBOLS] = [
    // 0-7
    6, 6, 6, 7, 7, 7, 7, 7,
    // 8-15
    7, 7, 7, 8, 8, 8, 8, 8,
    // 16-23
    8, 8, 9, 8, 9, 9, 9, 9,
    // 24-31
    8, 8, 9, 9, 9, 9, 9, 9,
    // 32-39
    8, 9, 9, 10, 9, 9, 9, 9,
    // 40-47
    9, 9, 9, 10, 9, 10, 10, 10,
    // 48-55
    9, 9, 10, 9, 10, 9, 10, 9,
    // 56-63
    9, 9, 10, 10, 9, 10, 9, 9,
    // 64-71
    8, 9, 9, 9, 9, 10, 10, 10,
    // 72-79
    9, 9, 10, 10, 10, 10, 10, 10,
    // 80-87
    9, 9, 10, 10, 10, 10, 10, 10,
    // 88-95
    10, 9, 10, 10, 10, 10, 10, 10,
    // 96-103
    8, 10, 10, 10, 10, 10, 10, 10,
    // 104-111
    10, 10, 10, 10, 10, 10, 10, 10,
    // 112-119
    9, 10, 10, 10, 10, 10, 10, 10,
    // 120-127
    9, 10, 10, 10, 10, 10, 10, 9,
    // 128-135
    7, 9, 9, 10, 9, 10, 10, 10,
    // 136-143
    9, 10, 10, 10, 10, 10, 10, 10,
    // 144-151
    9, 10, 10, 10, 10, 10, 10, 10,
    // 152-159
    10, 10, 10, 10, 10, 10, 10, 10,
    // 160-167
    10, 10, 10, 10, 10, 10, 10, 10,
    // 168-175
    10, 10, 10, 13, 10, 10, 10, 10,
    // 176-183
    10, 10, 11, 10, 10, 10, 10, 10,
    // 184-191
    10, 10, 10, 10, 10, 10, 10, 10,
    // 192-199
    9, 10, 10, 10, 10, 10, 9, 10,
    // 200-207
    10, 10, 10, 10, 9, 10, 10, 10,
    // 208-215
    9, 10, 10, 10, 10, 10, 10, 10,
    // 216-223
    10, 10, 10, 10, 10, 10, 10, 10,
    // 224-231
    9, 10, 10, 10, 10, 10, 10, 10,
    // 232-239
    10, 10, 10, 10, 10, 10, 9, 10,
    // 240-247
    8, 9, 9, 10, 9, 10, 10, 10,
    // 248-255
    9, 10, 10, 10, 9, 9, 8, 7,
    // 256-263 (256=EOS, 257=EOS variant, 258-263=copy-offset)
    13, 13, 7, 7, 10, 7, 7, 6,
    // 264-271 (copy-offset symbols)
    6, 6, 6, 5, 6, 6, 6, 5,
    // 272-279
    6, 5, 6, 6, 6, 6, 6, 6,
    // 280-287
    6, 6, 6, 6, 6, 6, 6, 6,
    // 288-293 (288=copy-offset, 289-292=cached, 293=EOS)
    8, 5, 6, 7, 7, 13,
];

/// Bit-lengths for 32 LOM Huffman codes.
#[rustfmt::skip]
const HUFF_LEN_LOM: [u8; NUM_LOM_SYMBOLS] = [
    4, 2, 3, 4, 3, 4, 4, 5,
    4, 5, 5, 6, 6, 7, 7, 8,
    7, 8, 8, 9, 9, 8, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9,
];

// ── Copy-offset LUTs (MS-RDPEGDI §3.1.8.1.4.1 Table 3) ──

/// Extra bits to read for each copy-offset symbol (indices 0-31).
#[rustfmt::skip]
const COPY_OFFSET_BITS: [u8; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2,
    3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10,
    11, 11, 12, 12, 13, 13, 14, 14,
];

/// Base value for each copy-offset symbol (indices 0-31).
#[rustfmt::skip]
const COPY_OFFSET_BASE: [u32; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13,
    17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073,
    4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
];

// ── LOM LUTs (MS-RDPEGDI §3.1.8.1.4.1 Table 6) ──

/// Extra bits to read for each LOM symbol (indices 0-29).
#[rustfmt::skip]
const LOM_BITS: [u8; NUM_LOM_LUT] = [
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4,
    6, 6, 8, 8, 14, 14,
];

/// Base value for each LOM symbol (indices 0-29).
#[rustfmt::skip]
const LOM_BASE: [u16; NUM_LOM_LUT] = [
    2, 3, 4, 5, 6, 7, 8, 9,
    10, 12, 14, 16, 18, 22, 26, 30,
    34, 42, 50, 58, 66, 82, 98, 114,
    130, 194, 258, 514, 2, 2,
];

// ── Compile-time Huffman lookup table generation ──

/// Build a flat Huffman decode table from canonical bit-lengths.
///
/// The table is indexed by the top `max_bits` of the MSB-first accumulator.
/// Each entry encodes `(symbol << 4) | code_length`.
/// Entry value 0 means "invalid code".
const fn build_decode_table<const NUM_SYM: usize, const TABLE_SIZE: usize>(
    lengths: &[u8; NUM_SYM],
    max_bits: u32,
) -> [u16; TABLE_SIZE] {
    let mut table = [0u16; TABLE_SIZE];

    // Step 1: Count codes at each bit-length.
    let mut bl_count = [0u32; 16];
    let mut i = 0;
    while i < NUM_SYM {
        if lengths[i] > 0 && (lengths[i] as u32) <= max_bits {
            bl_count[lengths[i] as usize] += 1;
        }
        i += 1;
    }

    // Step 2: Compute starting canonical code for each bit-length.
    let mut next_code = [0u32; 16];
    let mut code: u32 = 0;
    bl_count[0] = 0;
    let mut bits: u32 = 1;
    while bits <= max_bits {
        code = (code + bl_count[bits as usize - 1]) << 1;
        next_code[bits as usize] = code;
        bits += 1;
    }

    // Step 3: Assign canonical codes and fill the flat table.
    // Canonical codes are MSB-first, matching our MSB-first accumulator.
    // The accumulator's top `max_bits` bits directly index the table.
    let mut sym = 0;
    while sym < NUM_SYM {
        let len = lengths[sym] as u32;
        if len > 0 && len <= max_bits {
            let canonical = next_code[len as usize];
            next_code[len as usize] += 1;

            let shift = max_bits - len;
            let base_index = (canonical as usize) << shift;
            let count = 1usize << shift;
            let entry = ((sym as u16) << 4) | (len as u16);

            let mut j = 0;
            while j < count {
                table[base_index + j] = entry;
                j += 1;
            }
        }
        sym += 1;
    }

    table
}

/// Precomputed LEC decode table (8192 entries).
static LEC_TABLE: [u16; LEC_TABLE_SIZE] =
    build_decode_table::<NUM_LEC_SYMBOLS, LEC_TABLE_SIZE>(&HUFF_LEN_LEC, MAX_LEC_BITS);

/// Precomputed LOM decode table (512 entries).
static LOM_TABLE: [u16; LOM_TABLE_SIZE] =
    build_decode_table::<NUM_LOM_SYMBOLS, LOM_TABLE_SIZE>(&HUFF_LEN_LOM, MAX_LOM_BITS);

// ── NcrushDecompressor ──

/// NCRUSH decompressor (RDP 6.0).
#[derive(Debug)]
pub struct NcrushDecompressor {
    history: [u8; HISTORY_SIZE],
    offset: usize,
    /// LRU cache of 4 most recent copy-offsets.
    cache: [u32; OFFSET_CACHE_SIZE],
}

impl NcrushDecompressor {
    /// Create a new decompressor with zeroed history.
    pub fn new() -> Self {
        Self {
            history: [0u8; HISTORY_SIZE],
            offset: 0,
            cache: [0u32; OFFSET_CACHE_SIZE],
        }
    }

    /// Reinitialize history, offset, and cache.
    pub fn reset(&mut self) {
        self.history.fill(0);
        self.offset = 0;
        self.cache = [0u32; OFFSET_CACHE_SIZE];
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
        // Step 1: PACKET_FLUSHED — zero history, reset offset and cache
        if flags & PACKET_FLUSHED != 0 {
            self.reset();
        }

        // Step 2: PACKET_AT_FRONT — compact last 32KB to front (FreeRDP behavior).
        // Per MS-RDPEGDI §3.1.8.1, the server sets PACKET_AT_FRONT only when
        // HistoryOffset >= 65000, so offset >= 32768 is guaranteed in conforming
        // streams. The `else 0` branch handles malformed packets defensively
        // (no panic, history state becomes meaningless but safe).
        if flags & PACKET_AT_FRONT != 0 {
            self.history.copy_within(32768..HISTORY_SIZE, 0);
            self.offset = if self.offset >= 32768 {
                self.offset - 32768
            } else {
                0
            };
            self.cache = [0u32; OFFSET_CACHE_SIZE];
        }

        // Step 3: Decompress or copy literal
        if flags & PACKET_COMPRESSED != 0 {
            self.decompress_huffman(src, dst)
        } else {
            self.copy_literal(src, dst)
        }
    }

    /// Copy uncompressed data into history and output.
    ///
    /// Unlike MPPC which uses linear addressing with an overflow check,
    /// NCRUSH uses a circular buffer (modular arithmetic via `HISTORY_MASK`).
    /// Offset wraps around silently when it reaches `HISTORY_SIZE`, which is
    /// the intended design for the 64K ring buffer.
    fn copy_literal(&mut self, src: &[u8], dst: &mut Vec<u8>) -> Result<(), DecompressError> {
        for &b in src {
            self.history[self.offset & HISTORY_MASK] = b;
            self.offset = (self.offset + 1) & HISTORY_MASK;
        }
        dst.extend_from_slice(src);
        Ok(())
    }

    /// Decompress a Huffman-encoded bitstream.
    fn decompress_huffman(
        &mut self,
        src: &[u8],
        dst: &mut Vec<u8>,
    ) -> Result<(), DecompressError> {
        let mut reader = BitReader::new(src);

        loop {
            // Need at least the shortest LEC code (5 bits) to decode
            if reader.remaining() < 5 {
                break;
            }

            // Decode LEC symbol using flat lookup table
            let peek_bits = if reader.remaining() >= MAX_LEC_BITS {
                reader.peek(MAX_LEC_BITS)
            } else {
                // Pad with zeros for short remaining
                reader.peek(reader.remaining()) << (MAX_LEC_BITS - reader.remaining())
            };
            let entry = LEC_TABLE[peek_bits as usize];
            if entry == 0 {
                return Err(DecompressError::TruncatedBitstream);
            }
            let symbol = (entry >> 4) as usize;
            let code_len = (entry & 0xF) as u32;

            if reader.remaining() < code_len {
                break; // not enough bits for this code
            }
            reader.read_bits(code_len)?;

            match symbol {
                // Literal byte (0-255)
                0..=255 => {
                    self.history[self.offset & HISTORY_MASK] = symbol as u8;
                    self.offset = (self.offset + 1) & HISTORY_MASK;
                    dst.push(symbol as u8);
                }

                // EOS (256 or 293)
                256 | 293 => break,

                // New copy-offset (257-288)
                257..=288 => {
                    let lut_idx = symbol - 257;
                    let extra = COPY_OFFSET_BITS[lut_idx] as u32;
                    let stream_bits = if extra > 0 {
                        reader.read_bits(extra)?
                    } else {
                        0
                    };
                    // The spec (MS-RDPEGDI §3.1.8.1.4.1 Table 3) defines
                    // copy-offset symbols as distance = Base + extra_bits.
                    // Distances are 1-based in the spec, but our history uses
                    // 0-based indexing, so we subtract 1 to convert to a
                    // 0-based distance for the `do_copy` source calculation.
                    let copy_offset =
                        COPY_OFFSET_BASE[lut_idx] as usize + stream_bits as usize - 1;

                    if copy_offset == 0 {
                        return Err(DecompressError::InvalidCopyOffset);
                    }

                    // Update offset cache: push new offset to front
                    self.push_cache(copy_offset as u32);

                    // Decode LOM and execute copy
                    let lom = self.decode_lom(&mut reader)?;
                    self.do_copy(copy_offset, lom, dst);
                }

                // Cached copy-offset (289-292)
                289..=292 => {
                    let cache_idx = symbol - 289;
                    let copy_offset = self.cache[cache_idx] as usize;
                    if copy_offset == 0 {
                        return Err(DecompressError::InvalidCopyOffset);
                    }

                    // LRU promote
                    self.promote_cache(cache_idx);

                    // Decode LOM and execute copy
                    let lom = self.decode_lom(&mut reader)?;
                    self.do_copy(copy_offset, lom, dst);
                }

                _ => return Err(DecompressError::TruncatedBitstream),
            }
        }

        Ok(())
    }

    /// Decode a Length-of-Match value from the bitstream.
    fn decode_lom(&self, reader: &mut BitReader<'_>) -> Result<usize, DecompressError> {
        if reader.remaining() < 2 {
            return Err(DecompressError::TruncatedBitstream);
        }

        let peek_bits = if reader.remaining() >= MAX_LOM_BITS {
            reader.peek(MAX_LOM_BITS)
        } else {
            reader.peek(reader.remaining()) << (MAX_LOM_BITS - reader.remaining())
        };
        let entry = LOM_TABLE[peek_bits as usize];
        if entry == 0 {
            return Err(DecompressError::TruncatedBitstream);
        }
        let lom_idx = (entry >> 4) as usize;
        let code_len = (entry & 0xF) as u32;

        if reader.remaining() < code_len {
            return Err(DecompressError::TruncatedBitstream);
        }
        reader.read_bits(code_len)?;

        // LOM indices 30-31 have no corresponding LUT entry
        if lom_idx >= NUM_LOM_LUT {
            return Err(DecompressError::TruncatedBitstream);
        }

        let extra = LOM_BITS[lom_idx] as u32;
        let stream_bits = if extra > 0 {
            reader.read_bits(extra)?
        } else {
            0
        };
        Ok(LOM_BASE[lom_idx] as usize + stream_bits as usize)
    }

    /// Execute a replicating copy from history buffer.
    fn do_copy(&mut self, copy_offset: usize, lom: usize, dst: &mut Vec<u8>) {
        let src_start = self.offset.wrapping_sub(copy_offset) & HISTORY_MASK;
        for i in 0..lom {
            let src_idx = (src_start + i) & HISTORY_MASK;
            let b = self.history[src_idx];
            self.history[self.offset & HISTORY_MASK] = b;
            self.offset = (self.offset + 1) & HISTORY_MASK;
            dst.push(b);
        }
    }

    /// Push a new offset to the front of the cache, shifting others down.
    fn push_cache(&mut self, offset: u32) {
        // Check if already in cache; if so, just promote
        for i in 0..OFFSET_CACHE_SIZE {
            if self.cache[i] == offset {
                self.promote_cache(i);
                return;
            }
        }
        // Shift down and insert at front
        self.cache[3] = self.cache[2];
        self.cache[2] = self.cache[1];
        self.cache[1] = self.cache[0];
        self.cache[0] = offset;
    }

    /// Move cache entry at `idx` to front, shifting others down.
    fn promote_cache(&mut self, idx: usize) {
        if idx == 0 {
            return;
        }
        let val = self.cache[idx];
        let mut i = idx;
        while i > 0 {
            self.cache[i] = self.cache[i - 1];
            i -= 1;
        }
        self.cache[0] = val;
    }
}

impl Default for NcrushDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the LEC lookup table has no unfilled entries (all non-zero).
    #[test]
    fn lec_table_fully_populated() {
        for (i, &entry) in LEC_TABLE.iter().enumerate() {
            assert_ne!(entry, 0, "LEC table entry {i} is empty");
        }
    }

    /// Verify that the LOM lookup table has no unfilled entries (all non-zero).
    #[test]
    fn lom_table_fully_populated() {
        for (i, &entry) in LOM_TABLE.iter().enumerate() {
            assert_ne!(entry, 0, "LOM table entry {i} is empty");
        }
    }

    /// Verify known LEC symbol/length from the spec walkthrough.
    #[test]
    fn lec_table_spot_check() {
        // Symbol 1 (literal 0x01): the stream code should be at the top 6 bits.
        // From the walkthrough: byte 0x24 = 00100100, first 6 bits = 001001.
        // As 13-bit index: 001001_0000000 = 0x0480.
        let entry = LEC_TABLE[0x0480];
        let sym = entry >> 4;
        let len = entry & 0xF;
        assert_eq!(sym, 1, "symbol mismatch at 0x0480");
        assert_eq!(len, 6, "length mismatch for symbol 1");
    }

    /// Official test vector from MS-RDPEGDI §3.1.8.1 walkthrough.
    ///
    /// Input: 01 00 00 00 0a 00 0a 00 20 00 20 00 80 00 80 00
    /// Compressed: 24 89 d1 2e 79 64 32 60 c8 7d fd 6d 01 60 32 ee
    ///
    /// Note: The walkthrough test vector does not include an EOS marker.
    /// The caller should use the expected uncompressed length from the PDU
    /// header to truncate the output.
    #[test]
    fn official_test_vector() {
        let compressed: &[u8] = &[
            0x24, 0x89, 0xD1, 0x2E, 0x79, 0x64, 0x32, 0x60, 0xC8, 0x7D, 0xFD, 0x6D, 0x01, 0x60,
            0x32, 0xEE,
        ];
        let expected: &[u8] = &[
            0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x0A, 0x00, 0x20, 0x00, 0x20, 0x00, 0x80, 0x00,
            0x80, 0x00,
        ];

        let mut dec = NcrushDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(compressed, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();

        // The first 16 bytes must match; extra output from padding is ignored
        assert!(out.len() >= 16);
        assert_eq!(&out[..16], expected);
        assert_eq!(&dec.history[..16], expected);
    }

    /// Test with hand-crafted bitstream containing EOS.
    ///
    /// Encodes: literal 'A' (sym 65) + literal 'B' (sym 66) + EOS (sym 256).
    #[test]
    fn eos_terminates_stream() {
        // Build canonical codes for symbols 65, 66, and 256
        // From HUFF_LEN_LEC: sym 65 has length 9, sym 66 has length 9, sym 256 has length 13.
        //
        // We find the canonical codes by looking them up in the LEC table.
        let code_65 = find_canonical_code(65);
        let code_66 = find_canonical_code(66);
        let code_256 = find_canonical_code(256);

        // Build a bitstream: code_65 (9 bits) + code_66 (9 bits) + code_256 (13 bits) = 31 bits
        let mut bits: u64 = 0;
        let mut nbits: u32 = 0;
        // Write code_65 MSB-first
        bits |= (code_65 as u64) << (64 - 9);
        nbits += 9;
        bits |= (code_66 as u64) << (64 - 9 - 9);
        nbits += 9;
        bits |= (code_256 as u64) << (64 - 9 - 9 - 13);
        nbits += 13;

        // Convert to bytes
        let byte_len = (nbits + 7) / 8;
        let mut data = Vec::new();
        for i in 0..byte_len {
            data.push(((bits >> (56 - i * 8)) & 0xFF) as u8);
        }

        let mut dec = NcrushDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out)
            .unwrap();

        assert_eq!(out, b"AB");
    }

    /// Find the canonical code for a given symbol by scanning the LEC table.
    fn find_canonical_code(symbol: usize) -> u32 {
        let len = HUFF_LEN_LEC[symbol] as u32;
        for i in 0..LEC_TABLE_SIZE {
            let entry = LEC_TABLE[i];
            let sym = (entry >> 4) as usize;
            let code_len = (entry & 0xF) as u32;
            if sym == symbol && code_len == len {
                // The index represents the code left-shifted by (13 - len)
                return (i >> (MAX_LEC_BITS - len)) as u32;
            }
        }
        panic!("symbol {symbol} not found in LEC table");
    }

    /// Test uncompressed (raw) payload pass-through.
    #[test]
    fn uncompressed_passthrough() {
        let mut dec = NcrushDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(b"hello", PACKET_FLUSHED, &mut out).unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(dec.offset, 5);
    }

    /// Test PACKET_FLUSHED resets state.
    #[test]
    fn flushed_resets_state() {
        let mut dec = NcrushDecompressor::new();
        let mut out = Vec::new();
        dec.decompress(b"test", 0, &mut out).unwrap();
        dec.cache[0] = 42;

        out.clear();
        dec.decompress(b"new", PACKET_FLUSHED, &mut out).unwrap();
        assert_eq!(out, b"new");
        assert_eq!(dec.offset, 3);
        assert_eq!(dec.cache, [0, 0, 0, 0]);
    }

    /// Test cache push and promote operations.
    #[test]
    fn cache_operations() {
        let mut dec = NcrushDecompressor::new();

        // Push 4 different offsets
        dec.push_cache(10);
        assert_eq!(dec.cache, [10, 0, 0, 0]);

        dec.push_cache(20);
        assert_eq!(dec.cache, [20, 10, 0, 0]);

        dec.push_cache(30);
        assert_eq!(dec.cache, [30, 20, 10, 0]);

        dec.push_cache(40);
        assert_eq!(dec.cache, [40, 30, 20, 10]);

        // Push a 5th offset — oldest (10) is dropped
        dec.push_cache(50);
        assert_eq!(dec.cache, [50, 40, 30, 20]);

        // Promote cache[2] (30) to front
        dec.promote_cache(2);
        assert_eq!(dec.cache, [30, 50, 40, 20]);

        // Push a duplicate (50) — should promote, not add new
        dec.push_cache(50);
        assert_eq!(dec.cache, [50, 30, 40, 20]);
    }

    /// Test PACKET_AT_FRONT compaction behavior.
    #[test]
    fn at_front_compaction() {
        let mut dec = NcrushDecompressor::new();

        // Fill offset to 40000 (past 32768)
        dec.offset = 40000;
        dec.history[39999] = 0xAB;
        dec.cache = [5, 10, 15, 20];

        // AT_FRONT should compact last 32KB to front
        let mut out = Vec::new();
        dec.decompress(b"", PACKET_AT_FRONT, &mut out).unwrap();

        // history[32768..65536] → history[0..32768]
        // offset was 40000, now 40000 - 32768 = 7232
        assert_eq!(dec.offset, 7232);
        // The byte at old position 39999 should now be at 39999 - 32768 = 7231
        assert_eq!(dec.history[7231], 0xAB);
        // Cache should be cleared
        assert_eq!(dec.cache, [0, 0, 0, 0]);
    }

    /// Test sequential packets sharing history state.
    #[test]
    fn sequential_packets() {
        let mut dec = NcrushDecompressor::new();

        // Packet 1: uncompressed "abc"
        let mut out1 = Vec::new();
        dec.decompress(b"abc", PACKET_FLUSHED, &mut out1).unwrap();
        assert_eq!(out1, b"abc");
        assert_eq!(dec.offset, 3);

        // Packet 2: uncompressed "XY", should append after packet 1's data
        let mut out2 = Vec::new();
        dec.decompress(b"XY", 0, &mut out2).unwrap();
        assert_eq!(out2, b"XY");
        assert_eq!(dec.offset, 5);
        assert_eq!(&dec.history[..5], b"abcXY");
    }

    /// Test that copy-offset 0 (symbol 257, lut_idx=0) returns InvalidCopyOffset.
    #[test]
    fn copy_offset_zero_rejected() {
        // Symbol 257 has HUFF_LEN_LEC[257]=13, COPY_OFFSET_BITS[0]=0, COPY_OFFSET_BASE[0]=1
        // copy_offset = 1 + 0 - 1 = 0 → InvalidCopyOffset
        let code_257 = find_canonical_code(257);
        // We also need a valid LOM after it, but the error should fire before LOM decode.
        // Just encode symbol 257 (13 bits) + padding.
        let bits: u64 = (code_257 as u64) << (64 - 13);
        let data: Vec<u8> = (0..2).map(|i| ((bits >> (56 - i * 8)) & 0xFF) as u8).collect();

        let mut dec = NcrushDecompressor::new();
        // First write some history so the copy has context
        let mut dummy = Vec::new();
        dec.decompress(b"test", PACKET_FLUSHED, &mut dummy).unwrap();

        let mut out = Vec::new();
        let result = dec.decompress(&data, PACKET_COMPRESSED, &mut out);
        assert_eq!(result, Err(DecompressError::InvalidCopyOffset));
    }

    /// Test that LOM index 30 (out of LOMBaseLUT bounds) returns error.
    #[test]
    fn lom_index_30_rejected() {
        // Construct: literal 'A' (to have something in history) + copy-offset + LOM symbol 30
        let code_a = find_canonical_code(b'A' as usize); // literal 'A' = sym 65
        let len_a = HUFF_LEN_LEC[b'A' as usize] as u32;

        // Copy-offset symbol 258 (lut_idx=1, base=2, bits=0 → offset=1)
        let code_258 = find_canonical_code(258);
        let len_258 = HUFF_LEN_LEC[258] as u32;

        // LOM symbol 30 has HUFF_LEN_LOM[30]=9
        // Find its canonical code in the LOM table
        let lom_30_code = find_lom_canonical_code(30);
        let lom_30_len = HUFF_LEN_LOM[30] as u32;

        let mut bits: u64 = 0;
        let mut nbits: u32 = 0;
        bits |= (code_a as u64) << (64 - len_a);
        nbits += len_a;
        bits |= (code_258 as u64) << (64 - nbits - len_258);
        nbits += len_258;
        bits |= (lom_30_code as u64) << (64 - nbits - lom_30_len);
        nbits += lom_30_len;

        let byte_len = ((nbits + 7) / 8) as usize;
        let data: Vec<u8> = (0..byte_len)
            .map(|i| ((bits >> (56 - i * 8)) & 0xFF) as u8)
            .collect();

        let mut dec = NcrushDecompressor::new();
        let mut out = Vec::new();
        let result = dec.decompress(&data, PACKET_COMPRESSED | PACKET_FLUSHED, &mut out);
        assert_eq!(result, Err(DecompressError::TruncatedBitstream));
    }

    /// Find the canonical code for a given LOM symbol by scanning the LOM table.
    fn find_lom_canonical_code(symbol: usize) -> u32 {
        let len = HUFF_LEN_LOM[symbol] as u32;
        for i in 0..LOM_TABLE_SIZE {
            let entry = LOM_TABLE[i];
            let sym = (entry >> 4) as usize;
            let code_len = (entry & 0xF) as u32;
            if sym == symbol && code_len == len {
                return (i >> (MAX_LOM_BITS - len)) as u32;
            }
        }
        panic!("LOM symbol {symbol} not found in LOM table");
    }
}
