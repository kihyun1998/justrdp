//! MPPC — RDP 4.0 (8K) and RDP 5.0 (64K) bulk decompression (`[MS-RDPBCGR]` 3.1.8).
//!
//! Decompression only, one direction: one [`Mppc`] holds the history buffer the server's
//! compressor mirrors. Packets must be fed in arrival order, and a failed packet poisons it.

/// `PACKET_COMPRESSED`: the payload is MPPC-encoded.
pub const PACKET_COMPRESSED: u8 = 0x20;
/// `PACKET_AT_FRONT`: decompress to the start of the history buffer.
pub const PACKET_AT_FRONT: u8 = 0x40;
/// `PACKET_FLUSHED`: zero the history buffer before anything else.
pub const PACKET_FLUSHED: u8 = 0x80;

/// The MPPC variant, which fixes the history size and the copy-offset encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MppcLevel {
    /// RDP 4.0: 8 KB history (`PACKET_COMPR_TYPE_8K`).
    Rdp4,
    /// RDP 5.0: 64 KB history (`PACKET_COMPR_TYPE_64K`).
    Rdp5,
}

impl MppcLevel {
    /// The history buffer size in bytes.
    pub const fn history_size(self) -> usize {
        match self {
            Self::Rdp4 => 8 * 1024,
            Self::Rdp5 => 64 * 1024,
        }
    }
}

/// Why a packet could not be decompressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MppcError {
    /// A token ran past the end of the packet.
    Truncated,
    /// A length-of-match prefix longer than the level's table.
    InvalidLengthOfMatch,
    /// A copy-offset of zero, which names a byte not yet written.
    ZeroCopyOffset,
    /// Decompressed bytes would run past the end of the history buffer.
    HistoryOverflow {
        /// Where the write would end.
        end: usize,
    },
    /// A copy whose source would run past the end of the history buffer.
    CopySourceOutOfRange {
        /// The copy's first source index.
        start: usize,
        /// The copy's length.
        len: usize,
    },
    /// An earlier packet failed, so the history no longer mirrors the server's.
    Poisoned,
}

impl core::fmt::Display for MppcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("MPPC token truncated"),
            Self::InvalidLengthOfMatch => f.write_str("MPPC length-of-match prefix too long"),
            Self::ZeroCopyOffset => f.write_str("MPPC copy-offset of zero"),
            Self::HistoryOverflow { end } => {
                write!(f, "MPPC output ends at {end}, past the history")
            }
            Self::CopySourceOutOfRange { start, len } => {
                write!(
                    f,
                    "MPPC copy of {len} bytes from {start} runs past the history"
                )
            }
            Self::Poisoned => f.write_str("MPPC history poisoned by an earlier failure"),
        }
    }
}

impl std::error::Error for MppcError {}

/// One direction's MPPC decompressor: the history buffer and the offset into it.
#[derive(Debug, Clone)]
pub struct Mppc {
    level: MppcLevel,
    history: Box<[u8]>,
    offset: usize,
    poisoned: bool,
}

impl Mppc {
    /// A decompressor with a zero-filled history at offset 0.
    pub fn new(level: MppcLevel) -> Self {
        Self {
            level,
            history: vec![0; level.history_size()].into_boxed_slice(),
            offset: 0,
            poisoned: false,
        }
    }

    /// The level this decompressor was built for.
    pub fn level(&self) -> MppcLevel {
        self.level
    }

    /// Decompress one packet under its compression `flags` (the type nibble is ignored). Without
    /// [`PACKET_COMPRESSED`] the payload is returned as is, after [`PACKET_FLUSHED`] and
    /// [`PACKET_AT_FRONT`] are applied.
    pub fn decompress<'a>(&'a mut self, src: &'a [u8], flags: u8) -> Result<&'a [u8], MppcError> {
        if self.poisoned {
            return Err(MppcError::Poisoned);
        }
        if flags & PACKET_FLUSHED != 0 {
            self.history.fill(0);
            self.offset = 0;
        }
        if flags & PACKET_AT_FRONT != 0 {
            self.offset = 0;
        }
        if flags & PACKET_COMPRESSED == 0 {
            return Ok(src);
        }
        let start = self.offset;
        match self.decode(src) {
            Ok(end) => {
                self.offset = end;
                Ok(&self.history[start..end])
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    fn decode(&mut self, src: &[u8]) -> Result<usize, MppcError> {
        let size = self.history.len();
        let mut bits = BitReader::new(src);
        let mut pos = self.offset;
        while bits.remaining() >= 8 {
            if bits.read(1)? == 0 {
                let literal = bits.read(7)? as u8;
                pos = self.push(pos, literal)?;
                continue;
            }
            if bits.read(1)? == 0 {
                let literal = 0x80 | bits.read(7)? as u8;
                pos = self.push(pos, literal)?;
                continue;
            }
            let copy_offset = self.copy_offset(&mut bits)?;
            let len = self.length_of_match(&mut bits)?;
            if copy_offset == 0 {
                return Err(MppcError::ZeroCopyOffset);
            }
            let end = pos + len;
            if end > size {
                return Err(MppcError::HistoryOverflow { end });
            }
            let from = (pos + size - copy_offset % size) % size;
            if from + len > size {
                return Err(MppcError::CopySourceOutOfRange { start: from, len });
            }
            // Byte by byte: a source that overlaps the destination repeats what it just wrote.
            for i in 0..len {
                self.history[pos + i] = self.history[from + i];
            }
            pos = end;
        }
        Ok(pos)
    }

    fn push(&mut self, pos: usize, byte: u8) -> Result<usize, MppcError> {
        let slot = self
            .history
            .get_mut(pos)
            .ok_or(MppcError::HistoryOverflow { end: pos + 1 })?;
        *slot = byte;
        Ok(pos + 1)
    }

    /// The copy-offset after the leading `11` already read (3.1.8.4.1.2.1, 3.1.8.4.2.2.1).
    fn copy_offset(&self, bits: &mut BitReader<'_>) -> Result<usize, MppcError> {
        Ok(match self.level {
            MppcLevel::Rdp4 => {
                if bits.read(1)? == 0 {
                    bits.read(13)? as usize + 320
                } else if bits.read(1)? == 0 {
                    bits.read(8)? as usize + 64
                } else {
                    bits.read(6)? as usize
                }
            }
            MppcLevel::Rdp5 => {
                if bits.read(1)? == 0 {
                    bits.read(16)? as usize + 2368
                } else if bits.read(1)? == 0 {
                    bits.read(11)? as usize + 320
                } else if bits.read(1)? == 0 {
                    bits.read(8)? as usize + 64
                } else {
                    bits.read(6)? as usize
                }
            }
        })
    }

    /// The length-of-match (3.1.8.4.1.2.2, 3.1.8.4.2.2.2): `k` ones, a zero, then `k + 1` bits
    /// under an implicit leading one; a lone zero is 3.
    fn length_of_match(&self, bits: &mut BitReader<'_>) -> Result<usize, MppcError> {
        let max_ones = match self.level {
            MppcLevel::Rdp4 => 11,
            MppcLevel::Rdp5 => 14,
        };
        let mut ones = 0;
        while bits.read(1)? == 1 {
            ones += 1;
            if ones > max_ones {
                return Err(MppcError::InvalidLengthOfMatch);
            }
        }
        if ones == 0 {
            return Ok(3);
        }
        let width = ones + 1;
        Ok((1 << width) | bits.read(width)? as usize)
    }
}

/// MSB-first reader over one packet.
struct BitReader<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.src.len() * 8 - self.pos
    }

    fn read(&mut self, n: usize) -> Result<u32, MppcError> {
        if n > self.remaining() {
            return Err(MppcError::Truncated);
        }
        let mut value = 0u32;
        for _ in 0..n {
            let bit = self.src[self.pos / 8] >> (7 - self.pos % 8) & 1;
            value = value << 1 | u32::from(bit);
            self.pos += 1;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // `untrusted-decode-never-panics`: any packet sequence, at either level and under any
        // flags, is Ok or a typed error. The fuzz target (`fuzz/fuzz_targets/mppc.rs`) runs the
        // same property unbounded.
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn decompress_never_panics_on_arbitrary_packets(
            rdp5 in any::<bool>(),
            packets in proptest::collection::vec(
                (any::<u8>(), proptest::collection::vec(any::<u8>(), 0..=512)),
                1..=8,
            ),
        ) {
            let level = if rdp5 { MppcLevel::Rdp5 } else { MppcLevel::Rdp4 };
            let mut mppc = Mppc::new(level);
            for (flags, packet) in &packets {
                if let Ok(out) = mppc.decompress(packet, *flags) {
                    prop_assert!(out.len() <= level.history_size());
                }
            }
        }
    }

    /// Pack a spec-table bit string (`0`/`1`, spaces ignored) MSB first, zero-padded.
    fn bits(pattern: &str) -> Vec<u8> {
        let bits: Vec<u8> = pattern
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .map(|b| b - b'0')
            .collect();
        bits.chunks(8)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0u8, |byte, (i, bit)| byte | bit << (7 - i))
            })
            .collect()
    }

    /// Each byte below 0x80 as its own 8-bit literal (3.1.8.4.1.1).
    fn literals(text: &[u8]) -> String {
        text.iter().map(|b| format!("{b:08b} ")).collect()
    }

    const SENTENCE: &[u8] = b"for.whom.the.bell.tolls,.the.bell.tolls.for.thee!";

    /// `[MS-RDPBCGR]` 3.1.8.2.3's output, `for.whom.the.bell.tolls,<16,15>.<40,4><19,3>e!`,
    /// encoded by hand with the tables of `level`.
    fn spec_example(offset_prefix: &str) -> Vec<u8> {
        let copy = |offset: u8, lom: &str| format!("{offset_prefix}{offset:06b} {lom} ");
        bits(&format!(
            "{}{}{}{}{}{}",
            literals(b"for.whom.the.bell.tolls,"),
            copy(16, "110 111"), // length 15
            literals(b"."),
            copy(40, "10 00"), // length 4
            copy(19, "0"),     // length 3
            literals(b"e!"),
        ))
    }

    #[test]
    fn the_spec_example_decompresses_at_both_levels() {
        for (level, prefix) in [(MppcLevel::Rdp4, "1111"), (MppcLevel::Rdp5, "11111")] {
            let mut mppc = Mppc::new(level);
            let packet = spec_example(prefix);
            assert_eq!(
                mppc.decompress(&packet, PACKET_COMPRESSED | PACKET_AT_FRONT),
                Ok(SENTENCE),
                "{level:?}"
            );
        }
    }

    #[test]
    fn a_literal_above_0x7f_is_10_and_its_low_seven_bits() {
        let mut mppc = Mppc::new(MppcLevel::Rdp4);
        assert_eq!(
            mppc.decompress(&bits("10 1100111"), PACKET_COMPRESSED),
            Ok(&[0xE7][..])
        );
    }

    /// `n` literals counting up modulo 128, then one copy encoded by `tuple`; returns the copy.
    fn after_literals(level: MppcLevel, n: usize, tuple: &str) -> Result<Vec<u8>, MppcError> {
        let text: Vec<u8> = (0..n).map(|i| (i % 128) as u8).collect();
        let mut mppc = Mppc::new(level);
        let packet = bits(&format!("{}{tuple}", literals(&text)));
        mppc.decompress(&packet, PACKET_COMPRESSED)
            .map(|out| out[n..].to_vec())
    }

    /// The three bytes a length-3 copy from `n - offset` returns.
    fn three_from(n: usize, offset: usize) -> Vec<u8> {
        (n - offset..n - offset + 3)
            .map(|i| (i % 128) as u8)
            .collect()
    }

    #[test]
    fn every_copy_offset_range_reaches_its_byte() {
        // RDP4 (3.1.8.4.1.2.1, its own examples 3, 128 and 1024), each with length 3.
        assert_eq!(
            after_literals(MppcLevel::Rdp4, 128, "1111 000011 0"),
            Ok(three_from(128, 3))
        );
        assert_eq!(
            after_literals(MppcLevel::Rdp4, 128, "1110 01000000 0"),
            Ok(three_from(128, 128))
        );
        assert_eq!(
            after_literals(MppcLevel::Rdp4, 1100, "110 0001011000000 0"),
            Ok(three_from(1100, 1024))
        );
        // RDP5 (3.1.8.4.2.2.1): 3, 64 + 63, 320 + 1, 2368 + 2.
        assert_eq!(
            after_literals(MppcLevel::Rdp5, 128, "11111 000011 0"),
            Ok(three_from(128, 3))
        );
        assert_eq!(
            after_literals(MppcLevel::Rdp5, 128, "11110 00111111 0"),
            Ok(three_from(128, 127))
        );
        assert_eq!(
            after_literals(MppcLevel::Rdp5, 400, "1110 00000000001 0"),
            Ok(three_from(400, 321))
        );
        assert_eq!(
            after_literals(MppcLevel::Rdp5, 2400, "110 0000000000000010 0"),
            Ok(three_from(2400, 2370))
        );
    }

    #[test]
    fn every_length_of_match_range_copies_that_many_bytes() {
        // 3.1.8.4.1.2.2's examples 15 and 120, plus the 4..7 row, from offset 128 (byte 0).
        for (lom, len) in [("10 01", 5), ("110 111", 15), ("111110 111000", 120)] {
            let copied = after_literals(MppcLevel::Rdp4, 128, &format!("1110 01000000 {lom}"));
            assert_eq!(
                copied,
                Ok((0..len).map(|i| (i % 128) as u8).collect()),
                "{lom}"
            );
        }
        // 4097, the table's own example: longer than what lies behind it, so it overlaps.
        let copied = after_literals(
            MppcLevel::Rdp4,
            128,
            "1110 01000000 111111111110 000000000001",
        )
        .unwrap();
        assert_eq!(copied.len(), 4097);
        assert!(
            copied
                .iter()
                .enumerate()
                .all(|(i, &b)| b == (i % 128) as u8)
        );
        // RDP5's longest row (15 bits).
        let copied = after_literals(
            MppcLevel::Rdp5,
            128,
            "11110 01000000 111111111111110 000000000000000",
        )
        .unwrap();
        assert_eq!(copied.len(), 32768);
    }

    #[test]
    fn history_spans_packets_and_at_front_keeps_it() {
        let mut mppc = Mppc::new(MppcLevel::Rdp5);
        let abc = bits(&literals(b"abc"));
        let back_three = bits("11111 000011 0");
        assert_eq!(
            mppc.decompress(&abc, PACKET_COMPRESSED | PACKET_AT_FRONT),
            Ok(&b"abc"[..])
        );
        assert_eq!(
            mppc.decompress(&back_three, PACKET_COMPRESSED),
            Ok(&b"abc"[..])
        );
        // From 0, offset 3 wraps to the history's zero-filled end.
        assert_eq!(
            mppc.decompress(&back_three, PACKET_COMPRESSED | PACKET_AT_FRONT),
            Ok(&[0, 0, 0][..])
        );
    }

    #[test]
    fn packet_flushed_zeroes_the_history_even_uncompressed() {
        // After "abcdef", both flags restart at 0; a literal then a copy reaching forward to
        // index 3 (offset 65534 from 1, the 16-bit range: 2368 + 63166) reads "def" only if
        // the history kept it.
        let reach = bits(&format!("{}110 {:016b} 0", literals(b"x"), 65534 - 2368));
        for (flags, expected) in [(PACKET_FLUSHED, [0, 0, 0]), (PACKET_AT_FRONT, *b"def")] {
            let mut mppc = Mppc::new(MppcLevel::Rdp5);
            mppc.decompress(&bits(&literals(b"abcdef")), PACKET_COMPRESSED)
                .unwrap();
            assert_eq!(mppc.decompress(b"raw", flags), Ok(&b"raw"[..]));
            let out = mppc.decompress(&reach, PACKET_COMPRESSED).unwrap();
            assert_eq!(out[1..], expected, "flags {flags:#x}");
        }
    }

    #[test]
    fn an_uncompressed_packet_leaves_the_history_alone() {
        let mut mppc = Mppc::new(MppcLevel::Rdp5);
        mppc.decompress(&bits(&literals(b"abc")), PACKET_COMPRESSED)
            .unwrap();
        assert_eq!(mppc.decompress(b"zzz", 0), Ok(&b"zzz"[..]));
        assert_eq!(
            mppc.decompress(&bits("11111 000011 0"), PACKET_COMPRESSED),
            Ok(&b"abc"[..])
        );
    }

    #[test]
    fn malformed_packets_are_errors_and_poison_the_history() {
        let cases = [
            // The 13-bit offset fills both bytes; the length-of-match has nothing left.
            (bits("110 0000000000001"), MppcError::Truncated),
            (
                bits("1111 000011 111111111111 0"),
                MppcError::InvalidLengthOfMatch,
            ),
            (bits("1111 000000 0"), MppcError::ZeroCopyOffset),
            // From 2, offset 1, length 8191 ends at 8193.
            (
                bits(&format!(
                    "{}1111 000001 111111111110 111111111111",
                    literals(b"ab")
                )),
                MppcError::HistoryOverflow { end: 8193 },
            ),
        ];
        for (packet, error) in cases {
            let mut mppc = Mppc::new(MppcLevel::Rdp4);
            assert_eq!(
                mppc.decompress(&packet, PACKET_COMPRESSED),
                Err(error.clone())
            );
            assert_eq!(
                mppc.decompress(&bits(&literals(b"a")), PACKET_COMPRESSED),
                Err(MppcError::Poisoned),
                "{error:?}"
            );
        }
    }

    #[test]
    fn a_copy_whose_source_runs_past_the_end_is_refused() {
        // At position 2, offset 4 wraps to 8190; three bytes from there run past 8192.
        let mut mppc = Mppc::new(MppcLevel::Rdp4);
        let packet = bits(&format!("{}1111 000100 0", literals(b"ab")));
        assert_eq!(
            mppc.decompress(&packet, PACKET_COMPRESSED),
            Err(MppcError::CopySourceOutOfRange {
                start: 8190,
                len: 3
            })
        );
    }

    #[test]
    fn trailing_padding_under_eight_bits_is_ignored() {
        let mut mppc = Mppc::new(MppcLevel::Rdp4);
        // One literal plus a copy of 11 bits leaves 5 padding bits in the third byte.
        let packet = bits(&format!("{}1111 000001 0", literals(b"q")));
        assert_eq!(packet.len(), 3);
        assert_eq!(
            mppc.decompress(&packet, PACKET_COMPRESSED),
            Ok(&b"qqqq"[..])
        );
    }
}
