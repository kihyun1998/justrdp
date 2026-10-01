//! Play Sound PDU (`[MS-RDPBCGR]` 2.2.9.1.1.5): the server's instruction to play a beep, the
//! Share Data body of [`crate::share::PDU_TYPE2_PLAY_SOUND`]. A client that advertises
//! [`crate::capability::SOUND_FLAG_BEEPS`] MUST support it (2.2.7.1.11).
//!
//! Decode only: justrdp is a client and this PDU is server-to-client.

use crate::DecodeError;
use crate::cursor::ReadCursor;

/// Play Sound PDU Data (`TS_PLAY_SOUND_PDU_DATA`, 2.2.9.1.1.5.1) — the beep the server asks
/// for, as sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaySound {
    /// `duration` of the beep, in milliseconds.
    pub duration: u32,
    /// `frequency` of the beep, in hertz.
    pub frequency: u32,
}

impl PlaySound {
    /// Decode the Share Data body.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let duration = cur.read_u32_le()?;
        let frequency = cur.read_u32_le()?;
        Ok(Self {
            duration,
            frequency,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn play_sound(body: &[u8]) -> Result<PlaySound, DecodeError> {
        PlaySound::decode(&mut ReadCursor::new(body, "test"))
    }

    proptest! {
        // ADR-0008: the no-panic property for a server-controlled parser. Malformed bytes are a
        // typed `DecodeError`, never a panic; reaching the end without unwinding is the assertion.
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn decode_never_panics_on_arbitrary_input(
            data in proptest::collection::vec(any::<u8>(), 0..=32),
        ) {
            let _ = play_sound(&data);
        }
    }

    #[test]
    fn duration_then_frequency_little_endian() {
        // duration 300 ms, frequency 800 Hz — `[console]::beep(800, 300)`.
        let mut body = 300u32.to_le_bytes().to_vec();
        body.extend_from_slice(&800u32.to_le_bytes());
        assert_eq!(
            play_sound(&body).expect("an 8-byte body decodes"),
            PlaySound {
                duration: 300,
                frequency: 800
            }
        );
    }

    #[test]
    fn every_bit_of_both_fields_is_kept() {
        let body = [0x01, 0x02, 0x03, 0x84, 0x05, 0x06, 0x07, 0x88];
        assert_eq!(
            play_sound(&body).unwrap(),
            PlaySound {
                duration: 0x8403_0201,
                frequency: 0x8807_0605
            }
        );
    }

    #[test]
    fn a_truncated_body_is_a_typed_error() {
        for len in 0..8 {
            assert!(
                play_sound(&[0u8; 8][..len]).is_err(),
                "a {len}-byte body must not decode"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_left_unread() {
        let body = [1, 0, 0, 0, 2, 0, 0, 0, 0xEE];
        let mut cur = ReadCursor::new(&body, "test");
        let pdu = PlaySound::decode(&mut cur).unwrap();
        assert_eq!(
            pdu,
            PlaySound {
                duration: 1,
                frequency: 2
            }
        );
        assert_eq!(cur.remaining(), 1);
    }
}
