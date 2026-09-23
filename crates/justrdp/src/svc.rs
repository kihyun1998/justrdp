//! Static virtual channel reassembly (`[MS-RDPBCGR]` 3.1.5.2.2): one [`Reassembler`] per
//! channel turns the MCS-delivered chunks of that channel back into whole messages.
use justrdp_pdu::DecodeError;
use justrdp_pdu::svc::{
    CHANNEL_FLAG_FIRST, CHANNEL_FLAG_LAST, CHANNEL_FLAG_PACKET_COMPRESSED, ChannelChunk,
};

/// `CHANNEL_FLAG_SUSPEND` (`[MS-RDPBCGR]` 2.2.6.1.1).
pub(crate) const CHANNEL_FLAG_SUSPEND: u32 = 0x0000_0020;
/// `CHANNEL_FLAG_RESUME` (`[MS-RDPBCGR]` 2.2.6.1.1).
pub(crate) const CHANNEL_FLAG_RESUME: u32 = 0x0000_0040;

/// The largest message a host static channel delivers unless the host sets its own cap.
pub(crate) const CHANNEL_MESSAGE_CAP: usize = 64 << 20;

/// What one chunk completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reassembled {
    /// A whole message.
    Message(Vec<u8>),
    /// A message over the cap of a dropping reassembler, skipped without being buffered.
    Dropped {
        /// Its declared `totalLength`.
        total_length: usize,
    },
}

/// What a reassembler does with a message over its cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverCap {
    /// Refuse it with an error.
    Refuse,
    /// Skip its bytes and report it as [`Reassembled::Dropped`].
    Drop,
}

/// The reassembly state of one static channel: the message in flight, if any.
#[derive(Debug)]
pub(crate) struct Reassembler {
    /// The largest `totalLength` this channel delivers.
    cap: usize,
    over_cap: OverCap,
    /// The declared `totalLength` of the message in flight.
    expected: Option<usize>,
    /// The bytes of the message in flight received so far.
    received: usize,
    /// Whether the message in flight is over the cap and being skipped.
    dropping: bool,
    buffer: Vec<u8>,
}

impl Reassembler {
    /// A reassembler that refuses a message over `cap`.
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            cap,
            over_cap: OverCap::Refuse,
            expected: None,
            received: 0,
            dropping: false,
            buffer: Vec::new(),
        }
    }

    /// A reassembler that skips a message over `cap` and reports it.
    pub(crate) fn dropping(cap: usize) -> Self {
        Self {
            over_cap: OverCap::Drop,
            ..Self::new(cap)
        }
    }

    /// Change the cap. In drop mode a message already in flight keeps the decision its first
    /// chunk got; in refuse mode every chunk is checked against the current cap.
    pub(crate) fn set_cap(&mut self, cap: usize) {
        self.cap = cap;
    }

    /// Consume one MCS-delivered payload (`CHANNEL_PDU_HEADER` + chunk). Returns the whole
    /// message once its last chunk has arrived, or, in drop mode, [`Reassembled::Dropped`] for
    /// a message over the cap; `None` while one is still in flight or when the chunk carries no
    /// message data.
    pub(crate) fn push(&mut self, payload: &[u8]) -> Result<Option<Reassembled>, DecodeError> {
        let chunk = ChannelChunk::decode(payload)?;
        if chunk.flags & CHANNEL_FLAG_PACKET_COMPRESSED != 0 {
            return Err(DecodeError::InvalidField {
                field: "CHANNEL_PDU_HEADER.flags",
                reason: "compressed SVC chunk but compression was never advertised",
            });
        }
        if chunk.flags & (CHANNEL_FLAG_SUSPEND | CHANNEL_FLAG_RESUME) != 0 {
            tracing::debug!(
                target: "rdp_svc",
                flags = format_args!("{:#010x}", chunk.flags),
                "SVC suspend/resume chunk skipped"
            );
            return Ok(None);
        }
        let total = usize::try_from(chunk.total_length).unwrap_or(usize::MAX);
        let over = total > self.cap;
        if over && self.over_cap == OverCap::Refuse {
            self.reset();
            return Err(length_error("SVC message exceeds the reassembly cap"));
        }
        let first = chunk.flags & CHANNEL_FLAG_FIRST != 0;
        let last = chunk.flags & CHANNEL_FLAG_LAST != 0;

        if !first && !last && self.expected.is_none() {
            if chunk.data.len() != total {
                return Err(length_error(
                    "unchunked SVC message does not match its length",
                ));
            }
            if over {
                return Ok(Some(dropped(total, self.cap)));
            }
            return Ok(Some(Reassembled::Message(chunk.data.to_vec())));
        }
        if first {
            if self.expected.is_some() {
                self.reset();
                return Err(DecodeError::InvalidField {
                    field: "CHANNEL_PDU_HEADER.flags",
                    reason: "SVC first chunk while a message is in flight",
                });
            }
            self.expected = Some(total);
            self.dropping = over;
        } else {
            match self.expected {
                None => {
                    return Err(DecodeError::InvalidField {
                        field: "CHANNEL_PDU_HEADER.flags",
                        reason: "SVC continuation chunk without a first chunk",
                    });
                }
                Some(expected) if expected != total => {
                    self.reset();
                    return Err(length_error(
                        "SVC chunk length differs from its first chunk",
                    ));
                }
                Some(_) => {}
            }
        }
        if self
            .received
            .checked_add(chunk.data.len())
            .is_none_or(|received| received > total)
        {
            self.reset();
            return Err(length_error("SVC chunks exceed their declared length"));
        }
        self.received += chunk.data.len();
        if !self.dropping {
            self.buffer.extend_from_slice(chunk.data);
        }
        if !last {
            return Ok(None);
        }
        if self.received != total {
            self.reset();
            return Err(length_error(
                "SVC chunks fall short of their declared length",
            ));
        }
        let complete = if self.dropping {
            dropped(total, self.cap)
        } else {
            Reassembled::Message(core::mem::take(&mut self.buffer))
        };
        self.reset();
        Ok(Some(complete))
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.expected = None;
        self.received = 0;
        self.dropping = false;
    }
}

fn dropped(total_length: usize, cap: usize) -> Reassembled {
    tracing::warn!(
        target: "rdp_svc",
        total_length,
        cap,
        "SVC message over the channel's cap skipped"
    );
    Reassembled::Dropped { total_length }
}

fn length_error(reason: &'static str) -> DecodeError {
    DecodeError::InvalidField {
        field: "CHANNEL_PDU_HEADER.length",
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::svc::encode_chunks;

    /// A hand-built chunk: header + data.
    fn chunk(total: u32, flags: u32, data: &[u8]) -> Vec<u8> {
        let mut out = total.to_le_bytes().to_vec();
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    fn invalid_field(err: DecodeError) -> &'static str {
        match err {
            DecodeError::InvalidField { field, .. } => field,
            other => panic!("expected InvalidField, got {other:?}"),
        }
    }

    #[test]
    fn a_single_chunk_message_is_delivered_whole() {
        let mut r = Reassembler::new(1 << 20);
        let got = r.push(&chunk(3, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST, b"abc"));
        assert_eq!(got.unwrap(), Some(Reassembled::Message(b"abc".to_vec())));
    }

    #[test]
    fn a_chunked_message_is_delivered_once_its_last_chunk_arrives() {
        let message: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let chunks = encode_chunks(&message);
        assert_eq!(chunks.len(), 4);
        let mut r = Reassembler::new(1 << 20);
        for c in &chunks[..3] {
            assert_eq!(r.push(c).unwrap(), None);
        }
        assert_eq!(
            r.push(&chunks[3]).unwrap(),
            Some(Reassembled::Message(message))
        );
        // The machine is ready for the next message.
        let next = r.push(&chunk(1, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST, b"z"));
        assert_eq!(next.unwrap(), Some(Reassembled::Message(b"z".to_vec())));
    }

    /// 3.1.5.2.2: neither FIRST nor LAST, outside a sequence, is dispatched as it is.
    #[test]
    fn a_flagless_chunk_outside_a_sequence_is_a_whole_message() {
        let mut r = Reassembler::new(1 << 20);
        assert_eq!(
            r.push(&chunk(2, 0, b"hi")).unwrap(),
            Some(Reassembled::Message(b"hi".to_vec()))
        );
    }

    /// …and inside one it is a middle chunk, not a message of its own.
    #[test]
    fn a_flagless_chunk_inside_a_sequence_is_a_middle_chunk() {
        let mut r = Reassembler::new(1 << 20);
        assert_eq!(r.push(&chunk(3, CHANNEL_FLAG_FIRST, b"a")).unwrap(), None);
        assert_eq!(r.push(&chunk(3, 0, b"b")).unwrap(), None);
        assert_eq!(
            r.push(&chunk(3, CHANNEL_FLAG_LAST, b"c")).unwrap(),
            Some(Reassembled::Message(b"abc".to_vec()))
        );
    }

    #[test]
    fn a_last_chunk_without_a_first_is_refused() {
        let mut r = Reassembler::new(1 << 20);
        let err = r.push(&chunk(1, CHANNEL_FLAG_LAST, b"x")).unwrap_err();
        assert_eq!(invalid_field(err), "CHANNEL_PDU_HEADER.flags");
    }

    #[test]
    fn a_compressed_chunk_is_refused() {
        let mut r = Reassembler::new(1 << 20);
        let flags = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST | CHANNEL_FLAG_PACKET_COMPRESSED;
        let err = r.push(&chunk(1, flags, b"x")).unwrap_err();
        assert_eq!(invalid_field(err), "CHANNEL_PDU_HEADER.flags");
    }

    #[test]
    fn a_declared_length_over_the_cap_is_refused() {
        let mut r = Reassembler::new(4);
        let err = r.push(&chunk(5, CHANNEL_FLAG_FIRST, b"x")).unwrap_err();
        assert_eq!(invalid_field(err), "CHANNEL_PDU_HEADER.length");
        // At the cap is accepted.
        let whole = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
        assert_eq!(
            r.push(&chunk(4, whole, b"abcd")).unwrap(),
            Some(Reassembled::Message(b"abcd".to_vec()))
        );
    }

    /// The chunks must add up to the declared length: short, long, and a length that changes
    /// mid-sequence are all refused rather than delivered as a plausible message.
    #[test]
    fn chunks_that_do_not_add_up_to_the_declared_length_are_refused() {
        let whole = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
        let mut r = Reassembler::new(1 << 20);
        let short = r.push(&chunk(4, whole, b"abc")).unwrap_err();
        assert_eq!(invalid_field(short), "CHANNEL_PDU_HEADER.length");

        let mut r = Reassembler::new(1 << 20);
        assert_eq!(r.push(&chunk(2, CHANNEL_FLAG_FIRST, b"ab")).unwrap(), None);
        let long = r.push(&chunk(2, CHANNEL_FLAG_LAST, b"c")).unwrap_err();
        assert_eq!(invalid_field(long), "CHANNEL_PDU_HEADER.length");

        let mut r = Reassembler::new(1 << 20);
        // "a" + "b" would add up to the *new* length, so only the mid-sequence check sees it.
        assert_eq!(r.push(&chunk(3, CHANNEL_FLAG_FIRST, b"a")).unwrap(), None);
        let moved = r.push(&chunk(2, CHANNEL_FLAG_LAST, b"b")).unwrap_err();
        assert_eq!(invalid_field(moved), "CHANNEL_PDU_HEADER.length");

        let mut r = Reassembler::new(1 << 20);
        let lone = r.push(&chunk(3, 0, b"ab")).unwrap_err();
        assert_eq!(invalid_field(lone), "CHANNEL_PDU_HEADER.length");
    }

    /// An overrun is refused at the middle chunk that causes it, not at a last chunk that may
    /// never come: until then the buffer would grow past both the declared length and the cap.
    #[test]
    fn an_overrun_is_refused_at_the_chunk_that_causes_it() {
        let mut r = Reassembler::new(4);
        assert_eq!(r.push(&chunk(2, CHANNEL_FLAG_FIRST, b"ab")).unwrap(), None);
        let err = r.push(&chunk(2, 0, b"cdef")).unwrap_err();
        assert_eq!(invalid_field(err), "CHANNEL_PDU_HEADER.length");
    }

    /// A refused sequence leaves nothing behind: the next message starts clean.
    #[test]
    fn a_refused_sequence_does_not_leak_into_the_next_message() {
        let mut r = Reassembler::new(1 << 20);
        assert_eq!(r.push(&chunk(2, CHANNEL_FLAG_FIRST, b"ab")).unwrap(), None);
        assert!(r.push(&chunk(2, CHANNEL_FLAG_LAST, b"c")).is_err());
        // A flagless chunk is a whole message only outside a sequence, so it sees any residue.
        assert_eq!(
            r.push(&chunk(1, 0, b"z")).unwrap(),
            Some(Reassembled::Message(b"z".to_vec()))
        );
    }

    /// A FIRST while a message is in flight is refused, and the refusal leaves nothing behind.
    #[test]
    fn a_first_chunk_mid_sequence_is_refused() {
        let mut r = Reassembler::new(1 << 20);
        assert_eq!(r.push(&chunk(9, CHANNEL_FLAG_FIRST, b"old")).unwrap(), None);
        let whole = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
        let err = r.push(&chunk(3, whole, b"new")).unwrap_err();
        assert_eq!(invalid_field(err), "CHANNEL_PDU_HEADER.flags");
        assert_eq!(
            r.push(&chunk(1, 0, b"z")).unwrap(),
            Some(Reassembled::Message(b"z".to_vec()))
        );
    }

    /// SUSPEND and RESUME chunks carry no message data and leave a sequence in flight alone.
    #[test]
    fn suspend_and_resume_chunks_are_skipped() {
        let mut r = Reassembler::new(1 << 20);
        assert_eq!(r.push(&chunk(0, CHANNEL_FLAG_SUSPEND, b"")).unwrap(), None);
        assert_eq!(r.push(&chunk(2, CHANNEL_FLAG_FIRST, b"a")).unwrap(), None);
        assert_eq!(r.push(&chunk(0, CHANNEL_FLAG_RESUME, b"")).unwrap(), None);
        assert_eq!(
            r.push(&chunk(2, CHANNEL_FLAG_LAST, b"b")).unwrap(),
            Some(Reassembled::Message(b"ab".to_vec()))
        );
    }

    #[test]
    fn a_truncated_header_is_a_typed_error() {
        let mut r = Reassembler::new(1 << 20);
        assert!(matches!(
            r.push(&[1, 2, 3]).unwrap_err(),
            DecodeError::NotEnoughBytes { .. }
        ));
    }

    /// A message over the cap of a dropping reassembler is skipped whole: nothing is buffered,
    /// and its last chunk reports it once.
    #[test]
    fn a_message_over_the_cap_is_dropped_whole() {
        let mut r = Reassembler::dropping(4);
        assert_eq!(r.push(&chunk(6, CHANNEL_FLAG_FIRST, b"ab")).unwrap(), None);
        assert_eq!(r.push(&chunk(6, 0, b"cd")).unwrap(), None);
        assert!(r.buffer.is_empty() && r.buffer.capacity() == 0);
        assert_eq!(
            r.push(&chunk(6, CHANNEL_FLAG_LAST, b"ef")).unwrap(),
            Some(Reassembled::Dropped { total_length: 6 })
        );
        let whole = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
        assert_eq!(
            r.push(&chunk(4, whole, b"abcd")).unwrap(),
            Some(Reassembled::Message(b"abcd".to_vec()))
        );
    }

    #[test]
    fn a_single_chunk_over_the_cap_is_dropped() {
        let mut r = Reassembler::dropping(2);
        let whole = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
        assert_eq!(
            r.push(&chunk(3, whole, b"abc")).unwrap(),
            Some(Reassembled::Dropped { total_length: 3 })
        );
        assert_eq!(
            r.push(&chunk(3, 0, b"abc")).unwrap(),
            Some(Reassembled::Dropped { total_length: 3 })
        );
    }

    /// Dropping skips the bytes, not the checks: the chunks must still add up.
    #[test]
    fn a_dropped_message_is_still_checked() {
        let mut r = Reassembler::dropping(2);
        assert_eq!(r.push(&chunk(4, CHANNEL_FLAG_FIRST, b"ab")).unwrap(), None);
        let overrun = r.push(&chunk(4, 0, b"cde")).unwrap_err();
        assert_eq!(invalid_field(overrun), "CHANNEL_PDU_HEADER.length");

        let mut r = Reassembler::dropping(2);
        assert_eq!(r.push(&chunk(4, CHANNEL_FLAG_FIRST, b"ab")).unwrap(), None);
        let short = r.push(&chunk(4, CHANNEL_FLAG_LAST, b"c")).unwrap_err();
        assert_eq!(invalid_field(short), "CHANNEL_PDU_HEADER.length");

        let mut r = Reassembler::dropping(2);
        assert_eq!(r.push(&chunk(4, CHANNEL_FLAG_FIRST, b"ab")).unwrap(), None);
        let moved = r.push(&chunk(5, CHANNEL_FLAG_LAST, b"cd")).unwrap_err();
        assert_eq!(invalid_field(moved), "CHANNEL_PDU_HEADER.length");
        // A refused drop leaves nothing behind either.
        assert_eq!(
            r.push(&chunk(1, 0, b"z")).unwrap(),
            Some(Reassembled::Message(b"z".to_vec()))
        );
    }

    #[test]
    fn the_cap_can_be_raised() {
        let mut r = Reassembler::dropping(2);
        r.set_cap(3);
        let whole = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
        assert_eq!(
            r.push(&chunk(3, whole, b"abc")).unwrap(),
            Some(Reassembled::Message(b"abc".to_vec()))
        );
    }

    /// A dropped message's byte count is bounded only by its declared length, which on a 32-bit
    /// target reaches `usize::MAX`: the count must not overflow.
    #[test]
    fn a_dropped_count_near_its_limit_is_refused_not_overflowed() {
        let mut r = Reassembler::dropping(0);
        assert_eq!(
            r.push(&chunk(u32::MAX, CHANNEL_FLAG_FIRST, b"a")).unwrap(),
            None
        );
        r.received = usize::MAX - 1;
        let err = r.push(&chunk(u32::MAX, 0, b"bc")).unwrap_err();
        assert_eq!(invalid_field(err), "CHANNEL_PDU_HEADER.length");
    }

    /// The cap a message's first chunk met decides it: changing the cap mid-message changes
    /// neither a drop nor a delivery.
    #[test]
    fn a_cap_change_mid_message_waits_for_the_next_message() {
        let mut r = Reassembler::dropping(2);
        assert_eq!(r.push(&chunk(4, CHANNEL_FLAG_FIRST, b"ab")).unwrap(), None);
        r.set_cap(10);
        assert_eq!(
            r.push(&chunk(4, CHANNEL_FLAG_LAST, b"cd")).unwrap(),
            Some(Reassembled::Dropped { total_length: 4 })
        );
        assert_eq!(r.push(&chunk(4, CHANNEL_FLAG_FIRST, b"ab")).unwrap(), None);
        r.set_cap(2);
        assert_eq!(
            r.push(&chunk(4, CHANNEL_FLAG_LAST, b"cd")).unwrap(),
            Some(Reassembled::Message(b"abcd".to_vec()))
        );
    }
}
