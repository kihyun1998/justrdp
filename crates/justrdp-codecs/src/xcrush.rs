//! XCRUSH — RDP 6.1 bulk decompression (`[MS-RDPEGDI]` 2.2.2.4, 3.1.8.2): a level-1 match
//! decoder over a 2,000,000-byte history, chained after a level-2 RDP 5.0 [`Mppc`].
//!
//! Decompression only, one direction. Packets must be fed in arrival order, and a failed packet
//! poisons the decompressor.

use crate::mppc::{Mppc, MppcError, MppcLevel, PACKET_FLUSHED};

/// `L1_COMPRESSED`: match details precede the literals.
pub const L1_COMPRESSED: u8 = 0x01;
/// `L1_NO_COMPRESSION`: the level-1 payload is literals only.
pub const L1_NO_COMPRESSION: u8 = 0x02;
/// `L1_PACKET_AT_FRONT`: write from the start of the level-1 history.
pub const L1_PACKET_AT_FRONT: u8 = 0x04;
/// `L1_INNER_COMPRESSION`: the level-1 payload went through level-2, under `Level2ComprFlags`.
pub const L1_INNER_COMPRESSION: u8 = 0x10;

/// The level-1 history size (`[MS-RDPEGDI]` 3.1.8.2.1).
pub const HISTORY_SIZE: usize = 2_000_000;

/// One `RDP61_MATCH_DETAILS` on the wire: `MatchLength`, `MatchOutputOffset`,
/// `MatchHistoryOffset`.
const MATCH_DETAILS_LEN: usize = 8;

/// Why a packet could not be decompressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XcrushError {
    /// The packet, its match details or its literals ended early.
    Truncated,
    /// `Level1ComprFlags` names neither `L1_COMPRESSED` nor `L1_NO_COMPRESSION`.
    NoLevel1Payload,
    /// A match's `MatchOutputOffset` lies before the output already produced.
    MatchOutputBackwards {
        /// The offset the match names.
        match_output: usize,
        /// The output already produced.
        produced: usize,
    },
    /// A match's source runs past the history.
    MatchOutsideHistory {
        /// `MatchHistoryOffset`.
        start: usize,
        /// `MatchLength`.
        len: usize,
    },
    /// Decompressed bytes would run past the end of the history.
    HistoryOverflow {
        /// Where the write would end.
        end: usize,
    },
    /// The level-2 decompressor refused the payload.
    Level2(MppcError),
    /// An earlier packet failed, so the histories no longer mirror the server's.
    Poisoned,
}

impl core::fmt::Display for XcrushError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("XCRUSH packet truncated"),
            Self::NoLevel1Payload => f.write_str("XCRUSH level-1 flags name no payload"),
            Self::MatchOutputBackwards {
                match_output,
                produced,
            } => write!(
                f,
                "XCRUSH match at output offset {match_output} lies before {produced}"
            ),
            Self::MatchOutsideHistory { start, len } => {
                write!(
                    f,
                    "XCRUSH match of {len} bytes from {start} runs past the history"
                )
            }
            Self::HistoryOverflow { end } => {
                write!(f, "XCRUSH output ends at {end}, past the history")
            }
            Self::Level2(e) => write!(f, "XCRUSH level-2: {e}"),
            Self::Poisoned => f.write_str("XCRUSH history poisoned by an earlier failure"),
        }
    }
}

impl std::error::Error for XcrushError {}

/// One direction's XCRUSH decompressor: the level-1 history and the chained level-2 MPPC.
#[derive(Debug, Clone)]
pub struct Xcrush {
    history: Box<[u8]>,
    offset: usize,
    level2: Mppc,
    poisoned: bool,
}

impl Default for Xcrush {
    fn default() -> Self {
        Self::new()
    }
}

impl Xcrush {
    /// A decompressor with zero-filled histories at offset 0.
    pub fn new() -> Self {
        Self {
            history: vec![0; HISTORY_SIZE].into_boxed_slice(),
            offset: 0,
            level2: Mppc::new(MppcLevel::Rdp5),
            poisoned: false,
        }
    }

    /// Zero the level-1 history and move to its start: an outer `PACKET_FLUSHED` on a payload
    /// that is not compressed.
    pub fn flush(&mut self) {
        self.history.fill(0);
        self.offset = 0;
    }

    /// Decompress one `RDP61_COMPRESSED_DATA` under the packet's outer compression `flags`, of
    /// which only `PACKET_FLUSHED` (zero the level-1 history) applies here.
    pub fn decompress<'a>(&'a mut self, src: &'a [u8], flags: u8) -> Result<&'a [u8], XcrushError> {
        if self.poisoned {
            return Err(XcrushError::Poisoned);
        }
        match self.decode(src, flags) {
            Ok((start, end)) => Ok(&self.history[start..end]),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    /// Run both levels; returns the history range the packet wrote.
    fn decode(&mut self, src: &[u8], flags: u8) -> Result<(usize, usize), XcrushError> {
        let [l1, l2, ref body @ ..] = *src else {
            return Err(XcrushError::Truncated);
        };
        if flags & PACKET_FLUSHED != 0 {
            self.flush();
        }
        // Level2ComprFlags apply whenever level-2 ran, PACKET_FLUSHED alone included.
        let payload: &[u8] = if l1 & L1_INNER_COMPRESSION != 0 {
            self.level2
                .decompress(body, l2)
                .map_err(XcrushError::Level2)?
        } else {
            body
        };
        if l1 & L1_PACKET_AT_FRONT != 0 {
            self.offset = 0;
        }
        let (matches, literals) = if l1 & L1_NO_COMPRESSION != 0 {
            (&[][..], payload)
        } else if l1 & L1_COMPRESSED != 0 {
            let count = payload
                .get(..2)
                .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])))
                .ok_or(XcrushError::Truncated)?;
            let details_end = 2 + count * MATCH_DETAILS_LEN;
            if payload.len() < details_end {
                return Err(XcrushError::Truncated);
            }
            (&payload[2..details_end], &payload[details_end..])
        } else {
            return Err(XcrushError::NoLevel1Payload);
        };

        let history = &mut self.history;
        let start = self.offset;
        let mut pos = start;
        let mut literal = 0;
        let mut produced = 0;
        for details in matches.as_chunks::<MATCH_DETAILS_LEN>().0 {
            let len = usize::from(u16::from_le_bytes([details[0], details[1]]));
            let match_output = usize::from(u16::from_le_bytes([details[2], details[3]]));
            let from =
                u32::from_le_bytes([details[4], details[5], details[6], details[7]]) as usize;
            let gap =
                match_output
                    .checked_sub(produced)
                    .ok_or(XcrushError::MatchOutputBackwards {
                        match_output,
                        produced,
                    })?;
            put_literals(history, literals, &mut literal, &mut pos, gap)?;
            produced += gap;
            if from + len > HISTORY_SIZE {
                return Err(XcrushError::MatchOutsideHistory { start: from, len });
            }
            if pos + len > HISTORY_SIZE {
                return Err(XcrushError::HistoryOverflow { end: pos + len });
            }
            // Byte by byte: a source that overlaps the destination repeats what it just wrote.
            for i in 0..len {
                history[pos + i] = history[from + i];
            }
            pos += len;
            produced += len;
        }
        let rest = literals.len() - literal;
        put_literals(history, literals, &mut literal, &mut pos, rest)?;
        self.offset = pos;
        Ok((start, pos))
    }
}

/// Copy the next `n` literals into the history at `pos`, advancing both.
fn put_literals(
    history: &mut [u8],
    literals: &[u8],
    literal: &mut usize,
    pos: &mut usize,
    n: usize,
) -> Result<(), XcrushError> {
    let bytes = literals
        .get(*literal..*literal + n)
        .ok_or(XcrushError::Truncated)?;
    let end = *pos + n;
    history
        .get_mut(*pos..end)
        .ok_or(XcrushError::HistoryOverflow { end })?
        .copy_from_slice(bytes);
    *pos = end;
    *literal += n;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mppc::{PACKET_AT_FRONT, PACKET_COMPRESSED};
    use proptest::prelude::*;

    proptest! {
        // `untrusted-decode-never-panics`: any packet sequence under any outer flags is Ok or a
        // typed error. The fuzz target (`fuzz/fuzz_targets/xcrush.rs`) runs it unbounded.
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn decompress_never_panics_on_arbitrary_packets(
            packets in proptest::collection::vec(
                (any::<u8>(), proptest::collection::vec(any::<u8>(), 0..=256)),
                1..=6,
            ),
        ) {
            let mut xcrush = Xcrush::new();
            for (flags, packet) in &packets {
                let _ = xcrush.decompress(packet, *flags);
            }
        }
    }

    /// The packet's outer compression byte for type 3: `PACKET_COMPRESSED | PACKET_COMPR_TYPE_RDP61`.
    const OUTER: u8 = PACKET_COMPRESSED | 0x03;

    /// `RDP61_COMPRESSED_DATA` with the level-2 flags clear: the payload is level-1 bytes as is.
    fn raw(l1: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![l1, 0];
        packet.extend_from_slice(payload);
        packet
    }

    /// A level-1 payload of `MatchCount`, the matches and the literals.
    fn matched(matches: &[(u16, u16, u32)], literals: &[u8]) -> Vec<u8> {
        let mut payload = (matches.len() as u16).to_le_bytes().to_vec();
        for &(len, output, history) in matches {
            payload.extend_from_slice(&len.to_le_bytes());
            payload.extend_from_slice(&output.to_le_bytes());
            payload.extend_from_slice(&history.to_le_bytes());
        }
        payload.extend_from_slice(literals);
        payload
    }

    /// `[MS-RDPEGDI]` 4.7's two packets, verbatim. Every byte is below 0x80, which RDP 5.0
    /// encodes as an 8-bit literal of itself, so the second packet's `PACKET_COMPRESSED` level-2
    /// payload is its own decompressed form: the bytes run the whole chain unchanged. The
    /// outputs are 3.1.8.2.3.1's.
    #[test]
    fn the_spec_example_decompresses() {
        let mut xcrush = Xcrush::new();
        let first = [
            0x16, 0x80, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
        ];
        assert_eq!(xcrush.decompress(&first, OUTER), Ok(&b"abcdefghij"[..]));
        let second = [
            0x11, 0x21, 0x02, 0x00, 0x09, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x75,
        ];
        assert_eq!(
            xcrush.decompress(&second, OUTER),
            Ok(&b"klmnodefghijklabcdu"[..])
        );
    }

    #[test]
    fn level_2_runs_before_level_1() {
        // Level-2: "ab" as literals, then an RDP 5.0 copy of offset 2, length 3: "ababa".
        // Level-1 reads that as five literals.
        let mut level2 = vec![0x61, 0x62];
        level2.extend_from_slice(&[0b1111_1000, 0b0100_0000]);
        let mut packet = vec![
            L1_INNER_COMPRESSION | L1_NO_COMPRESSION,
            PACKET_COMPRESSED | 0x01,
        ];
        packet.extend_from_slice(&level2);
        assert_eq!(Xcrush::new().decompress(&packet, OUTER), Ok(&b"ababa"[..]));
    }

    /// `Level2ComprFlags` reach the level-2 history whenever `L1_INNER_COMPRESSION` is set,
    /// `PACKET_FLUSHED` without `PACKET_COMPRESSED` included.
    #[test]
    fn a_level_2_flush_without_compression_still_resets_level_2() {
        let inner = L1_INNER_COMPRESSION | L1_NO_COMPRESSION;
        // Level-2 offset 3, length 3: the three bytes before the write position.
        let back_three = [0b1111_1000, 0b0110_0000];
        for (l2_flags, expected) in [(PACKET_FLUSHED, [0u8, 0, 0]), (0, *b"abc")] {
            let mut xcrush = Xcrush::new();
            let mut first = vec![inner, PACKET_COMPRESSED | 0x01];
            first.extend_from_slice(b"abc");
            xcrush.decompress(&first, OUTER).unwrap();
            xcrush.decompress(&[inner, l2_flags, b'x'], OUTER).unwrap();
            let mut copy = vec![inner, PACKET_COMPRESSED | 0x01];
            copy.extend_from_slice(&back_three);
            assert_eq!(
                xcrush.decompress(&copy, OUTER),
                Ok(&expected[..]),
                "Level2ComprFlags {l2_flags:#x}"
            );
        }
    }

    /// `L1_PACKET_AT_FRONT` moves the write position to 0 and keeps the history: a match after
    /// it still reads the bytes written before.
    #[test]
    fn l1_packet_at_front_resets_the_offset_and_keeps_the_history() {
        let mut xcrush = Xcrush::new();
        xcrush
            .decompress(&raw(L1_NO_COMPRESSION, b"abcdefghij"), OUTER)
            .unwrap();
        assert_eq!(
            xcrush.decompress(&raw(L1_PACKET_AT_FRONT | L1_NO_COMPRESSION, b"XY"), OUTER),
            Ok(&b"XY"[..])
        );
        // At offset 2 now: copy three bytes from history offset 5.
        assert_eq!(
            xcrush.decompress(&raw(L1_COMPRESSED, &matched(&[(3, 0, 5)], b"")), OUTER),
            Ok(&b"fgh"[..])
        );
    }

    #[test]
    fn an_outer_flush_zeroes_the_level_1_history() {
        let mut xcrush = Xcrush::new();
        xcrush
            .decompress(&raw(L1_NO_COMPRESSION, b"abcdefghij"), OUTER)
            .unwrap();
        assert_eq!(
            xcrush.decompress(&raw(L1_NO_COMPRESSION, b"Q"), OUTER | PACKET_FLUSHED),
            Ok(&b"Q"[..])
        );
        assert_eq!(
            xcrush.decompress(&raw(L1_COMPRESSED, &matched(&[(3, 0, 5)], b"")), OUTER),
            Ok(&[0, 0, 0][..])
        );
    }

    #[test]
    fn literals_surround_matches_in_output_order() {
        let mut xcrush = Xcrush::new();
        xcrush
            .decompress(&raw(L1_NO_COMPRESSION, b"0123456789"), OUTER)
            .unwrap();
        // "ab", match "234" at output 2, "c", match "78" at output 6, then "de".
        let payload = matched(&[(3, 2, 2), (2, 6, 7)], b"abcde");
        assert_eq!(
            xcrush.decompress(&raw(L1_COMPRESSED, &payload), OUTER),
            Ok(&b"ab234c78de"[..])
        );
    }

    #[test]
    fn a_match_may_read_bytes_written_earlier_in_the_same_packet() {
        // "ab" at 0..2, then a 6-byte match from history offset 0 overlapping its own output.
        let payload = matched(&[(6, 2, 0)], b"ab");
        assert_eq!(
            Xcrush::new().decompress(&raw(L1_COMPRESSED, &payload), OUTER),
            Ok(&b"abababab"[..])
        );
    }

    #[test]
    fn malformed_packets_are_errors_and_poison_the_decompressor() {
        let cases = [
            (vec![L1_NO_COMPRESSION], XcrushError::Truncated),
            (raw(0, b"abc"), XcrushError::NoLevel1Payload),
            (raw(L1_COMPRESSED, &[2, 0, 1]), XcrushError::Truncated),
            (
                raw(L1_COMPRESSED, &matched(&[(1, 3, 0)], b"ab")),
                XcrushError::Truncated,
            ),
            (
                raw(
                    L1_COMPRESSED,
                    &matched(&[(2, 0, HISTORY_SIZE as u32 - 1)], b""),
                ),
                XcrushError::MatchOutsideHistory {
                    start: HISTORY_SIZE - 1,
                    len: 2,
                },
            ),
            (
                raw(L1_COMPRESSED, &matched(&[(1, 1, 0), (1, 0, 0)], b"a")),
                XcrushError::MatchOutputBackwards {
                    match_output: 0,
                    produced: 2,
                },
            ),
            (
                vec![
                    L1_INNER_COMPRESSION | L1_NO_COMPRESSION,
                    PACKET_COMPRESSED | 0x01,
                    0xFF,
                ],
                XcrushError::Level2(MppcError::Truncated),
            ),
        ];
        for (packet, error) in cases {
            let mut xcrush = Xcrush::new();
            xcrush
                .decompress(&raw(L1_NO_COMPRESSION, b"z"), OUTER)
                .unwrap();
            assert_eq!(
                xcrush.decompress(&packet, OUTER),
                Err(error.clone()),
                "{packet:?}"
            );
            assert_eq!(
                xcrush.decompress(&raw(L1_NO_COMPRESSION, b"a"), OUTER),
                Err(XcrushError::Poisoned),
                "{error:?}"
            );
        }
    }

    #[test]
    fn output_past_the_history_end_is_refused() {
        let mut xcrush = Xcrush::new();
        let fill = vec![0x41; HISTORY_SIZE - 1];
        xcrush
            .decompress(&raw(L1_NO_COMPRESSION, &fill), OUTER)
            .unwrap();
        assert_eq!(
            xcrush.decompress(&raw(L1_NO_COMPRESSION, b"ab"), OUTER),
            Err(XcrushError::HistoryOverflow {
                end: HISTORY_SIZE + 1
            })
        );
    }

    #[test]
    fn packet_at_front_flags_reach_level_2_too() {
        // Level-2 PACKET_AT_FRONT: from 0, offset 3 wraps into level-2's zeroed tail.
        let inner = L1_INNER_COMPRESSION | L1_NO_COMPRESSION;
        let mut xcrush = Xcrush::new();
        let mut first = vec![inner, PACKET_COMPRESSED | 0x01];
        first.extend_from_slice(b"abc");
        xcrush.decompress(&first, OUTER).unwrap();
        let copy = [
            inner,
            PACKET_COMPRESSED | PACKET_AT_FRONT | 0x01,
            0b1111_1000,
            0b0110_0000,
        ];
        assert_eq!(xcrush.decompress(&copy, OUTER), Ok(&[0u8, 0, 0][..]));
    }
}
