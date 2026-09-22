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

/// The largest message a host static channel accepts.
pub(crate) const CHANNEL_MESSAGE_CAP: usize = 64 << 20;

/// The reassembly state of one static channel: the message in flight, if any.
#[derive(Debug)]
pub(crate) struct Reassembler {
    /// The largest `totalLength` this channel accepts.
    cap: usize,
    /// The declared `totalLength` of the message in flight.
    expected: Option<usize>,
    buffer: Vec<u8>,
}

impl Reassembler {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            cap,
            expected: None,
            buffer: Vec::new(),
        }
    }

    /// Consume one MCS-delivered payload (`CHANNEL_PDU_HEADER` + chunk). Returns the whole
    /// message once its last chunk has arrived, `None` while one is still in flight or when
    /// the chunk carries no message data.
    pub(crate) fn push(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>, DecodeError> {
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
        if total > self.cap {
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
            return Ok(Some(chunk.data.to_vec()));
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
        if self.buffer.len() + chunk.data.len() > total {
            self.reset();
            return Err(length_error("SVC chunks exceed their declared length"));
        }
        self.buffer.extend_from_slice(chunk.data);
        if !last {
            return Ok(None);
        }
        if self.buffer.len() != total {
            self.reset();
            return Err(length_error(
                "SVC chunks fall short of their declared length",
            ));
        }
        self.expected = None;
        Ok(Some(core::mem::take(&mut self.buffer)))
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.expected = None;
    }
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
        assert_eq!(got.unwrap(), Some(b"abc".to_vec()));
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
        assert_eq!(r.push(&chunks[3]).unwrap(), Some(message));
        // The machine is ready for the next message.
        let next = r.push(&chunk(1, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST, b"z"));
        assert_eq!(next.unwrap(), Some(b"z".to_vec()));
    }

    /// 3.1.5.2.2: neither FIRST nor LAST, outside a sequence, is dispatched as it is.
    #[test]
    fn a_flagless_chunk_outside_a_sequence_is_a_whole_message() {
        let mut r = Reassembler::new(1 << 20);
        assert_eq!(r.push(&chunk(2, 0, b"hi")).unwrap(), Some(b"hi".to_vec()));
    }

    /// …and inside one it is a middle chunk, not a message of its own.
    #[test]
    fn a_flagless_chunk_inside_a_sequence_is_a_middle_chunk() {
        let mut r = Reassembler::new(1 << 20);
        assert_eq!(r.push(&chunk(3, CHANNEL_FLAG_FIRST, b"a")).unwrap(), None);
        assert_eq!(r.push(&chunk(3, 0, b"b")).unwrap(), None);
        assert_eq!(
            r.push(&chunk(3, CHANNEL_FLAG_LAST, b"c")).unwrap(),
            Some(b"abc".to_vec())
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
            Some(b"abcd".to_vec())
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
        assert_eq!(r.push(&chunk(1, 0, b"z")).unwrap(), Some(b"z".to_vec()));
    }

    /// A FIRST while a message is in flight is refused, and the refusal leaves nothing behind.
    #[test]
    fn a_first_chunk_mid_sequence_is_refused() {
        let mut r = Reassembler::new(1 << 20);
        assert_eq!(r.push(&chunk(9, CHANNEL_FLAG_FIRST, b"old")).unwrap(), None);
        let whole = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
        let err = r.push(&chunk(3, whole, b"new")).unwrap_err();
        assert_eq!(invalid_field(err), "CHANNEL_PDU_HEADER.flags");
        assert_eq!(r.push(&chunk(1, 0, b"z")).unwrap(), Some(b"z".to_vec()));
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
            Some(b"ab".to_vec())
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
}
