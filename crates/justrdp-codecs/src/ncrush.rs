//! NCRUSH — RDP 6.0 bulk decompression (`[MS-RDPEGDI]` 3.1.8.1): Huffman-coded literals,
//! copy-offsets and lengths of match over a 65,536-byte history, with a four-entry cache of
//! recent copy-offsets.
//!
//! Decompression only, one direction. Packets must be fed in arrival order, and a failed packet
//! poisons the decompressor.

use std::sync::LazyLock;

use crate::mppc::{PACKET_AT_FRONT, PACKET_COMPRESSED, PACKET_FLUSHED};

/// The history size (`[MS-RDPEGDI]` 3.1.8.1.1).
pub const HISTORY_SIZE: usize = 65_536;

/// Where `PACKET_AT_FRONT` leaves the write position after sliding the history back by half.
const HALF: usize = HISTORY_SIZE / 2;

/// `LiteralOrEosOrCopyOffset` index of the end-of-stream marker.
const EOS: u16 = 256;

/// `HuffLengthLEC` (`[MS-RDPEGDI]` 3.1.8.1.4.1, Table 1).
const HUFF_LENGTH_LEC: [u8; 293] = [
    6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 9, 8, 9, 9, 9, 9, 8, 8, 9, 9, 9, 9, 9, 9,
    8, 9, 9, 10, 9, 9, 9, 9, 9, 9, 9, 10, 9, 10, 10, 10, 9, 9, 10, 9, 10, 9, 10, 9, 9, 9, 10, 10,
    9, 10, 9, 9, 8, 9, 9, 9, 9, 10, 10, 10, 9, 9, 10, 10, 10, 10, 10, 10, 9, 9, 10, 10, 10, 10, 10,
    10, 10, 9, 10, 10, 10, 10, 10, 10, 8, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 9, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 9, 7, 9, 9, 10, 9, 10, 10, 10, 9,
    10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 13, 10, 10, 10, 10, 10, 10, 11, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 9, 10, 10, 10, 9, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 9, 10, 8, 9, 9, 10, 9, 10, 10, 10, 9, 10, 10, 10, 9, 9, 8, 7, 13, 13, 7, 7, 10,
    7, 7, 6, 6, 6, 6, 5, 6, 6, 6, 5, 6, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 8, 5, 6, 7, 7,
];

/// `HuffCodeLEC` (Table 2): each code as it appears on the wire, least significant bit first.
const HUFF_CODE_LEC: [u16; 293] = [
    0x0004, 0x0024, 0x0014, 0x0011, 0x0051, 0x0031, 0x0071, 0x0009, 0x0049, 0x0029, 0x0069, 0x0015,
    0x0095, 0x0055, 0x00d5, 0x0035, 0x00b5, 0x0075, 0x001d, 0x00f5, 0x011d, 0x009d, 0x019d, 0x005d,
    0x000d, 0x008d, 0x015d, 0x00dd, 0x01dd, 0x003d, 0x013d, 0x00bd, 0x004d, 0x01bd, 0x007d, 0x006b,
    0x017d, 0x00fd, 0x01fd, 0x0003, 0x0103, 0x0083, 0x0183, 0x026b, 0x0043, 0x016b, 0x036b, 0x00eb,
    0x0143, 0x00c3, 0x02eb, 0x01c3, 0x01eb, 0x0023, 0x03eb, 0x0123, 0x00a3, 0x01a3, 0x001b, 0x021b,
    0x0063, 0x011b, 0x0163, 0x00e3, 0x00cd, 0x01e3, 0x0013, 0x0113, 0x0093, 0x031b, 0x009b, 0x029b,
    0x0193, 0x0053, 0x019b, 0x039b, 0x005b, 0x025b, 0x015b, 0x035b, 0x0153, 0x00d3, 0x00db, 0x02db,
    0x01db, 0x03db, 0x003b, 0x023b, 0x013b, 0x01d3, 0x033b, 0x00bb, 0x02bb, 0x01bb, 0x03bb, 0x007b,
    0x002d, 0x027b, 0x017b, 0x037b, 0x00fb, 0x02fb, 0x01fb, 0x03fb, 0x0007, 0x0207, 0x0107, 0x0307,
    0x0087, 0x0287, 0x0187, 0x0387, 0x0033, 0x0047, 0x0247, 0x0147, 0x0347, 0x00c7, 0x02c7, 0x01c7,
    0x0133, 0x03c7, 0x0027, 0x0227, 0x0127, 0x0327, 0x00a7, 0x00b3, 0x0019, 0x01b3, 0x0073, 0x02a7,
    0x0173, 0x01a7, 0x03a7, 0x0067, 0x00f3, 0x0267, 0x0167, 0x0367, 0x00e7, 0x02e7, 0x01e7, 0x03e7,
    0x01f3, 0x0017, 0x0217, 0x0117, 0x0317, 0x0097, 0x0297, 0x0197, 0x0397, 0x0057, 0x0257, 0x0157,
    0x0357, 0x00d7, 0x02d7, 0x01d7, 0x03d7, 0x0037, 0x0237, 0x0137, 0x0337, 0x00b7, 0x02b7, 0x01b7,
    0x03b7, 0x0077, 0x0277, 0x07ff, 0x0177, 0x0377, 0x00f7, 0x02f7, 0x01f7, 0x03f7, 0x03ff, 0x000f,
    0x020f, 0x010f, 0x030f, 0x008f, 0x028f, 0x018f, 0x038f, 0x004f, 0x024f, 0x014f, 0x034f, 0x00cf,
    0x000b, 0x02cf, 0x01cf, 0x03cf, 0x002f, 0x022f, 0x010b, 0x012f, 0x032f, 0x00af, 0x02af, 0x01af,
    0x008b, 0x03af, 0x006f, 0x026f, 0x018b, 0x016f, 0x036f, 0x00ef, 0x02ef, 0x01ef, 0x03ef, 0x001f,
    0x021f, 0x011f, 0x031f, 0x009f, 0x029f, 0x019f, 0x039f, 0x005f, 0x004b, 0x025f, 0x015f, 0x035f,
    0x00df, 0x02df, 0x01df, 0x03df, 0x003f, 0x023f, 0x013f, 0x033f, 0x00bf, 0x02bf, 0x014b, 0x01bf,
    0x00ad, 0x00cb, 0x01cb, 0x03bf, 0x002b, 0x007f, 0x027f, 0x017f, 0x012b, 0x037f, 0x00ff, 0x02ff,
    0x00ab, 0x01ab, 0x006d, 0x0059, 0x17ff, 0x0fff, 0x0039, 0x0079, 0x01ff, 0x0005, 0x0045, 0x0034,
    0x000c, 0x002c, 0x001c, 0x0000, 0x003c, 0x0002, 0x0022, 0x0010, 0x0012, 0x0008, 0x0032, 0x000a,
    0x002a, 0x001a, 0x003a, 0x0006, 0x0026, 0x0016, 0x0036, 0x000e, 0x002e, 0x001e, 0x003e, 0x0001,
    0x00ed, 0x0018, 0x0021, 0x0025, 0x0065,
];

/// `CopyOffsetBitsLUT` (Table 3).
const COPY_OFFSET_BITS: [u8; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14,
];

/// `CopyOffsetBaseLUT` (Table 3).
const COPY_OFFSET_BASE: [u32; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
];

/// `HuffLengthL` (3.1.8.1.4.2, Table 4).
const HUFF_LENGTH_LOM: [u8; 32] = [
    4, 2, 3, 4, 3, 4, 4, 5, 4, 5, 5, 6, 6, 7, 7, 8, 7, 8, 8, 9, 9, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
];

/// `HuffCodeL` (Table 5), least significant bit first.
const HUFF_CODE_LOM: [u16; 32] = [
    0x0001, 0x0000, 0x0002, 0x0009, 0x0006, 0x0005, 0x000d, 0x000b, 0x0003, 0x001b, 0x0007, 0x0017,
    0x0037, 0x000f, 0x004f, 0x006f, 0x002f, 0x00ef, 0x001f, 0x005f, 0x015f, 0x009f, 0x00df, 0x01df,
    0x003f, 0x013f, 0x00bf, 0x01bf, 0x007f, 0x017f, 0x00ff, 0x01ff,
];

/// `LoMBitsLUT` (Table 6). Only 30 entries: codes 30 and 31 have none.
const LOM_BITS: [u8; 30] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 6, 6, 8, 8, 14, 14,
];

/// `LoMBaseLUT` (Table 6).
const LOM_BASE: [u32; 30] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 18, 22, 26, 30, 34, 42, 50, 58, 66, 82, 98, 114, 130,
    194, 258, 514, 2, 2,
];

/// Why a packet could not be decompressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NcrushError {
    /// The stream ended before its end-of-stream marker.
    Truncated,
    /// A bit pattern that is no code of the table being read, or a length-of-match code with no
    /// base (30 and 31).
    InvalidCode,
    /// A copy-offset of zero, which names the byte being written.
    ZeroCopyOffset,
    /// `PACKET_AT_FRONT` with no more than half a history written: there is nothing to slide.
    NothingToSlide {
        /// The write position.
        offset: usize,
    },
    /// Decompressed bytes would run past the end of the history.
    HistoryOverflow {
        /// Where the write would end.
        end: usize,
    },
    /// A copy whose source would run past the end of the history.
    CopySourceOutOfRange {
        /// The copy's first source index.
        start: usize,
        /// The copy's length.
        len: usize,
    },
    /// An earlier packet failed, so the history no longer mirrors the server's.
    Poisoned,
}

impl core::fmt::Display for NcrushError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("NCRUSH stream ended before its end-of-stream marker"),
            Self::InvalidCode => f.write_str("NCRUSH bit pattern matches no code"),
            Self::ZeroCopyOffset => f.write_str("NCRUSH copy-offset of zero"),
            Self::NothingToSlide { offset } => {
                write!(
                    f,
                    "NCRUSH PACKET_AT_FRONT at offset {offset}: nothing to slide"
                )
            }
            Self::HistoryOverflow { end } => {
                write!(f, "NCRUSH output ends at {end}, past the history")
            }
            Self::CopySourceOutOfRange { start, len } => {
                write!(
                    f,
                    "NCRUSH copy of {len} bytes from {start} runs past the history"
                )
            }
            Self::Poisoned => f.write_str("NCRUSH history poisoned by an earlier failure"),
        }
    }
}

impl std::error::Error for NcrushError {}

/// One direction's NCRUSH decompressor: the history, the write position and the offset cache.
#[derive(Debug, Clone)]
pub struct Ncrush {
    history: Box<[u8]>,
    offset: usize,
    cache: [usize; 4],
    poisoned: bool,
}

impl Default for Ncrush {
    fn default() -> Self {
        Self::new()
    }
}

impl Ncrush {
    /// A decompressor with a zero-filled history at offset 0 and an empty offset cache.
    pub fn new() -> Self {
        Self {
            history: vec![0; HISTORY_SIZE].into_boxed_slice(),
            offset: 0,
            cache: [0; 4],
            poisoned: false,
        }
    }

    /// Decompress one packet under its compression `flags` (the type nibble is ignored). Without
    /// [`PACKET_COMPRESSED`] the payload is returned as is, after [`PACKET_FLUSHED`] and
    /// [`PACKET_AT_FRONT`] are applied.
    pub fn decompress<'a>(&'a mut self, src: &'a [u8], flags: u8) -> Result<&'a [u8], NcrushError> {
        if self.poisoned {
            return Err(NcrushError::Poisoned);
        }
        match self.decode(src, flags) {
            Ok(None) => Ok(src),
            Ok(Some((start, end))) => Ok(&self.history[start..end]),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    /// Apply the flags and decode; `None` for a payload that is not compressed.
    fn decode(&mut self, src: &[u8], flags: u8) -> Result<Option<(usize, usize)>, NcrushError> {
        if flags & PACKET_FLUSHED != 0 {
            // A flush leaves nothing a slide could keep: PACKET_AT_FRONT has no further effect.
            self.history.fill(0);
            self.offset = 0;
            self.cache = [0; 4];
        } else if flags & PACKET_AT_FRONT != 0 {
            if self.offset <= HALF {
                return Err(NcrushError::NothingToSlide {
                    offset: self.offset,
                });
            }
            self.history.copy_within(self.offset - HALF..self.offset, 0);
            self.history[HALF..].fill(0);
            self.offset = HALF;
        }
        if flags & PACKET_COMPRESSED == 0 {
            return Ok(None);
        }

        let mut bits = Reader { src, pos: 0 };
        let start = self.offset;
        let mut pos = start;
        loop {
            let symbol = bits.symbol(&LEC_DECODE, MAX_LEC_LEN)?;
            if symbol < 256 {
                let slot = self
                    .history
                    .get_mut(pos)
                    .ok_or(NcrushError::HistoryOverflow { end: pos + 1 })?;
                *slot = symbol as u8;
                pos += 1;
                continue;
            }
            if symbol == EOS {
                break;
            }
            let copy_offset = if symbol < 289 {
                let index = usize::from(symbol - 257);
                let base = COPY_OFFSET_BASE[index] as usize;
                let offset = base + bits.read(usize::from(COPY_OFFSET_BITS[index]))? as usize - 1;
                self.cache.copy_within(0..3, 1);
                self.cache[0] = offset;
                offset
            } else {
                let slot = usize::from(symbol - 289);
                self.cache.swap(0, slot);
                self.cache[0]
            };
            let index = usize::from(bits.symbol(&LOM_DECODE, MAX_LOM_LEN)?);
            if index >= LOM_BASE.len() {
                return Err(NcrushError::InvalidCode);
            }
            let len = LOM_BASE[index] as usize + bits.read(usize::from(LOM_BITS[index]))? as usize;
            if copy_offset == 0 {
                return Err(NcrushError::ZeroCopyOffset);
            }
            let end = pos + len;
            if end > HISTORY_SIZE {
                return Err(NcrushError::HistoryOverflow { end });
            }
            let from = (pos + HISTORY_SIZE - copy_offset % HISTORY_SIZE) % HISTORY_SIZE;
            if from + len > HISTORY_SIZE {
                return Err(NcrushError::CopySourceOutOfRange { start: from, len });
            }
            // Byte by byte: a source that overlaps the destination repeats what it just wrote.
            for i in 0..len {
                self.history[pos + i] = self.history[from + i];
            }
            pos = end;
        }
        self.offset = pos;
        Ok(Some((start, pos)))
    }
}

/// The longest `LiteralOrEosOrCopyOffset` code.
const MAX_LEC_LEN: usize = 13;
/// The longest `LengthOfMatch` code.
const MAX_LOM_LEN: usize = 9;

/// A least-significant-bit-first reader over one packet.
struct Reader<'a> {
    src: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn remaining(&self) -> usize {
        self.src.len() * 8 - self.pos
    }

    /// The next `n` bits, zero past the end.
    fn peek(&self, n: usize) -> u32 {
        (0..n).fold(0, |value, i| {
            let bit = self
                .src
                .get((self.pos + i) / 8)
                .map_or(0, |byte| byte >> ((self.pos + i) % 8) & 1);
            value | u32::from(bit) << i
        })
    }

    fn read(&mut self, n: usize) -> Result<u32, NcrushError> {
        if n > self.remaining() {
            return Err(NcrushError::Truncated);
        }
        let value = self.peek(n);
        self.pos += n;
        Ok(value)
    }

    /// Decode one Huffman code through `table`, indexed by the next `max` bits.
    fn symbol(&mut self, table: &[u16], max: usize) -> Result<u16, NcrushError> {
        let entry = table[self.peek(max) as usize];
        let len = usize::from(entry >> 12);
        if entry == 0 {
            return Err(NcrushError::InvalidCode);
        }
        if len > self.remaining() {
            return Err(NcrushError::Truncated);
        }
        self.pos += len;
        Ok(entry & 0x0FFF)
    }
}

/// A decode table indexed by the next `max` stream bits (least significant first): each entry is
/// `length << 12 | symbol`, 0 where no code fits.
fn decode_table(lengths: &[u8], codes: &[u16]) -> Box<[u16]> {
    let max = usize::from(*lengths.iter().max().expect("a non-empty table"));
    let mut table = vec![0u16; 1 << max].into_boxed_slice();
    for (symbol, (&len, &code)) in lengths.iter().zip(codes).enumerate() {
        let len = usize::from(len);
        for high in 0..1usize << (max - len) {
            table[usize::from(code) | high << len] = (len as u16) << 12 | symbol as u16;
        }
    }
    table
}

static LEC_DECODE: LazyLock<Box<[u16]>> =
    LazyLock::new(|| decode_table(&HUFF_LENGTH_LEC, &HUFF_CODE_LEC));
static LOM_DECODE: LazyLock<Box<[u16]>> =
    LazyLock::new(|| decode_table(&HUFF_LENGTH_LOM, &HUFF_CODE_LOM));

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // `untrusted-decode-never-panics`: any packet sequence under any flags is Ok or a typed
        // error. The fuzz target (`fuzz/fuzz_targets/ncrush.rs`) runs it unbounded.
        #![proptest_config(ProptestConfig::with_cases(1024))]
        #[test]
        fn decompress_never_panics_on_arbitrary_packets(
            packets in proptest::collection::vec(
                (any::<u8>(), proptest::collection::vec(any::<u8>(), 0..=256)),
                1..=6,
            ),
        ) {
            let mut ncrush = Ncrush::new();
            for (flags, packet) in &packets {
                if let Ok(out) = ncrush.decompress(packet, *flags) {
                    prop_assert!(out.len() <= HISTORY_SIZE.max(packet.len()));
                }
            }
        }
    }

    /// A least-significant-bit-first writer: the stream's own bit order.
    #[derive(Default)]
    struct Bits {
        bytes: Vec<u8>,
        len: usize,
    }

    impl Bits {
        fn put(&mut self, value: u32, n: usize) -> &mut Self {
            for i in 0..n {
                if self.len.is_multiple_of(8) {
                    self.bytes.push(0);
                }
                let bit = (value >> i & 1) as u8;
                *self.bytes.last_mut().unwrap() |= bit << (self.len % 8);
                self.len += 1;
            }
            self
        }

        fn lec(&mut self, index: usize) -> &mut Self {
            self.put(
                u32::from(HUFF_CODE_LEC[index]),
                usize::from(HUFF_LENGTH_LEC[index]),
            )
        }

        fn lom_code(&mut self, index: usize) -> &mut Self {
            self.put(
                u32::from(HUFF_CODE_LOM[index]),
                usize::from(HUFF_LENGTH_LOM[index]),
            )
        }

        fn literals(&mut self, text: &[u8]) -> &mut Self {
            for &b in text {
                self.lec(usize::from(b));
            }
            self
        }

        /// A length of match by 3.1.8.1.4.3.2's rule, from table rows 0-27.
        fn lom(&mut self, len: u32) -> &mut Self {
            let index = (0..28).rev().find(|&i| LOM_BASE[i] <= len).unwrap();
            self.lom_code(index)
                .put(len - LOM_BASE[index], usize::from(LOM_BITS[index]))
        }

        /// A copy-tuple by 3.1.8.1.4.3.1's rule.
        fn copy(&mut self, offset: u32, len: u32) -> &mut Self {
            let index = (0..32)
                .rev()
                .find(|&i| COPY_OFFSET_BASE[i] <= offset + 1)
                .unwrap();
            self.lec(257 + index)
                .put(
                    offset + 1 - COPY_OFFSET_BASE[index],
                    usize::from(COPY_OFFSET_BITS[index]),
                )
                .lom(len)
        }

        fn cached(&mut self, slot: usize, len: u32) -> &mut Self {
            self.lec(289 + slot).lom(len)
        }

        fn eos(&mut self) -> Vec<u8> {
            self.lec(usize::from(EOS));
            std::mem::take(&mut self.bytes)
        }
    }

    const COMPRESSED: u8 = PACKET_COMPRESSED | 0x02;

    /// The canonical Huffman algorithm the spec names ([SAYOOD] 4.2.4): codes in order of
    /// (length, symbol), each the previous plus one, shifted left as the length grows.
    fn canonical(lengths: &[u8]) -> Vec<u16> {
        let mut order: Vec<usize> = (0..lengths.len()).collect();
        order.sort_by_key(|&s| (lengths[s], s));
        let mut codes = vec![0u16; lengths.len()];
        let (mut code, mut prev) = (0u16, lengths[order[0]]);
        for (n, &s) in order.iter().enumerate() {
            if n > 0 {
                code = (code + 1) << (lengths[s] - prev);
            }
            prev = lengths[s];
            codes[s] = code;
        }
        codes
    }

    /// Table 2 and Table 5 follow from Tables 1 and 4: each code is the canonical one with its
    /// bits reversed, the stream being least significant bit first. A mistranscribed length or
    /// code in either table fails this.
    #[test]
    fn the_codebooks_are_the_canonical_codes_of_their_lengths() {
        for (lengths, codes) in [
            (&HUFF_LENGTH_LEC[..], &HUFF_CODE_LEC[..]),
            (&HUFF_LENGTH_LOM[..], &HUFF_CODE_LOM[..]),
        ] {
            for (symbol, (canonical, (&len, &code))) in canonical(lengths)
                .into_iter()
                .zip(lengths.iter().zip(codes))
                .enumerate()
            {
                let reversed = canonical.reverse_bits() >> (16 - u32::from(len));
                assert_eq!(code, reversed, "symbol {symbol}");
            }
        }
    }

    /// 3.1.8.1.4.4.1.1 and 3.1.8.1.4.4.2.1's decoding examples: code 0x0034 (index 263) with
    /// extra bits 0 and 3 is offset 8 and 11; length codes 0x0001, and 0x01df with extra bits
    /// 3, are 2 and 117.
    #[test]
    fn the_spec_decoding_examples_hold() {
        assert_eq!((HUFF_CODE_LEC[263], HUFF_LENGTH_LEC[263]), (0x0034, 6));
        assert_eq!((HUFF_CODE_LOM[0], HUFF_CODE_LOM[23]), (0x0001, 0x01df));
        let text = b"0123456789ab";
        for (extra, offset) in [(0u32, 8usize), (3, 11)] {
            for (lom_index, lom_extra, len) in [(0usize, 0u32, 2usize), (23, 3, 117)] {
                let packet = Bits::default()
                    .literals(text)
                    .lec(263)
                    .put(extra, 2)
                    .lom_code(lom_index)
                    .put(lom_extra, usize::from(LOM_BITS[lom_index]))
                    .eos();
                let mut ncrush = Ncrush::new();
                let out = ncrush.decompress(&packet, COMPRESSED).unwrap().to_vec();
                let copied = &out[text.len()..];
                assert_eq!(copied.len(), len, "offset {offset}, length {len}");
                for i in 0..len {
                    let expected = out[text.len() - offset + i];
                    assert_eq!(copied[i], expected, "offset {offset}, byte {i}");
                }
            }
        }
    }

    #[test]
    fn literals_of_every_value_round_trip() {
        let text: Vec<u8> = (0..=255).collect();
        let packet = Bits::default().literals(&text).eos();
        assert_eq!(Ncrush::new().decompress(&packet, COMPRESSED), Ok(&text[..]));
    }

    #[test]
    fn every_copy_offset_and_length_range_round_trips() {
        // 40,000 counting bytes, then copies at every offset row that fits, with lengths from
        // every row 0-27.
        let text: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let mut expected = text.clone();
        let mut bits = Bits::default();
        bits.literals(&text);
        let offsets = COPY_OFFSET_BASE
            .iter()
            .map(|&b| b - 1)
            .filter(|&o| (1..40_000).contains(&o));
        let lengths = LOM_BASE[..28].iter().copied().cycle();
        for (offset, len) in offsets.zip(lengths) {
            for _ in 0..len {
                expected.push(expected[expected.len() - offset as usize]);
            }
            bits.copy(offset, len);
        }
        let packet = bits.eos();
        let mut ncrush = Ncrush::new();
        assert_eq!(
            ncrush.decompress(&packet, COMPRESSED).map(<[u8]>::to_vec),
            Ok(expected)
        );
    }

    #[test]
    fn the_offset_cache_takes_new_offsets_in_front_and_swaps_hits_to_it() {
        let text = b"abcdefghij";
        let mut expected = text.to_vec();
        let mut bits = Bits::default();
        bits.literals(text);
        // Copies at offsets 2, 3, 5, 7: the cache is then [7, 5, 3, 2].
        for offset in [2u32, 3, 5, 7] {
            bits.copy(offset, 2);
            for _ in 0..2 {
                expected.push(expected[expected.len() - offset as usize]);
            }
        }
        // Slot 2 holds 3 and swaps to the front: [3, 5, 7, 2]. Slot 3 then holds 2: [2, 5, 7, 3].
        // Slot 0 is 2 again.
        for (slot, offset) in [(2usize, 3usize), (3, 2), (0, 2)] {
            bits.cached(slot, 4);
            for _ in 0..4 {
                expected.push(expected[expected.len() - offset]);
            }
        }
        let packet = bits.eos();
        assert_eq!(
            Ncrush::new()
                .decompress(&packet, COMPRESSED)
                .map(<[u8]>::to_vec),
            Ok(expected)
        );
    }

    #[test]
    fn history_spans_packets() {
        let mut ncrush = Ncrush::new();
        let first = Bits::default().literals(b"hello").eos();
        assert_eq!(ncrush.decompress(&first, COMPRESSED), Ok(&b"hello"[..]));
        let second = Bits::default().copy(5, 5).eos();
        assert_eq!(ncrush.decompress(&second, COMPRESSED), Ok(&b"hello"[..]));
    }

    #[test]
    fn packet_at_front_slides_the_history_back_by_half() {
        let mut ncrush = Ncrush::new();
        let text: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        ncrush
            .decompress(&Bits::default().literals(&text).eos(), COMPRESSED)
            .unwrap();
        // At 40,000: bytes 7,232..40,000 move to 0..32,768 and the write position is 32,768.
        // Offset 5 from there reads what was at 39,995.
        let copy = Bits::default().copy(5, 3).eos();
        assert_eq!(
            ncrush.decompress(&copy, COMPRESSED | PACKET_AT_FRONT),
            Ok(&text[39_995..39_998])
        );
        // From 32,771, offset 32,771 reaches index 0 of the slid history: what was at 7,232.
        let start = Bits::default().copy(32_771, 2).eos();
        assert_eq!(
            ncrush.decompress(&start, COMPRESSED),
            Ok(&text[7_232..7_234])
        );
        // The second half was zeroed: offset 3 back from 32,773 is 32,770, just written, but
        // a copy from 32,800 (offset 65,509 wraps there) reads zeros.
        let zeros = Bits::default().copy(65_509, 2).eos();
        assert_eq!(ncrush.decompress(&zeros, COMPRESSED), Ok(&[0u8, 0][..]));
    }

    #[test]
    fn packet_at_front_with_nothing_to_slide_is_an_error() {
        let mut ncrush = Ncrush::new();
        ncrush
            .decompress(&Bits::default().literals(b"abc").eos(), COMPRESSED)
            .unwrap();
        assert_eq!(
            ncrush.decompress(b"", PACKET_AT_FRONT),
            Err(NcrushError::NothingToSlide { offset: 3 })
        );
    }

    #[test]
    fn packet_flushed_zeroes_the_history_and_empties_the_cache() {
        let mut ncrush = Ncrush::new();
        let filled = Bits::default().literals(b"abcdef").copy(3, 2).eos();
        ncrush.decompress(&filled, COMPRESSED).unwrap();
        // FLUSHED with AT_FRONT: no slide error, the history is zero and the write position 0.
        assert_eq!(
            ncrush.decompress(b"raw", PACKET_FLUSHED | PACKET_AT_FRONT),
            Ok(&b"raw"[..])
        );
        // Offset 4 from 1 wraps to the zeroed end, where "abcdef" would otherwise not be.
        let wrapped = Bits::default().literals(b"x").copy(4, 2).eos();
        assert_eq!(ncrush.decompress(&wrapped, COMPRESSED), Ok(&b"x\0\0"[..]));
        // The flush emptied the cache, so after that copy it is [4, 0, 0, 0]; unflushed, slot 1
        // would still hold the 3 from before.
        let cached = Bits::default().literals(b"q").cached(1, 2).eos();
        assert_eq!(
            ncrush.decompress(&cached, COMPRESSED),
            Err(NcrushError::ZeroCopyOffset)
        );
    }

    #[test]
    fn malformed_packets_are_errors_and_poison_the_decompressor() {
        let cases = [
            (
                Bits::default().literals(b"ab").bytes.clone(),
                NcrushError::Truncated,
            ),
            (
                Bits::default().literals(b"ab").lec(257).lom_code(30).eos(),
                NcrushError::InvalidCode,
            ),
            // From 1, offset 2 wraps to the last byte: three bytes from there run past the end.
            (
                Bits::default().literals(b"a").copy(2, 3).eos(),
                NcrushError::CopySourceOutOfRange {
                    start: HISTORY_SIZE - 1,
                    len: 3,
                },
            ),
        ];
        for (packet, error) in cases {
            let mut ncrush = Ncrush::new();
            assert_eq!(ncrush.decompress(&packet, COMPRESSED), Err(error.clone()));
            let next = Bits::default().literals(b"a").eos();
            assert_eq!(
                ncrush.decompress(&next, COMPRESSED),
                Err(NcrushError::Poisoned),
                "{error:?}"
            );
        }
    }
}
