#![no_main]
//! Fuzz the audio input channel (#401): the `[MS-RDPEAI]` PDU parser and the helper that
//! drives it. Sibling of audin's `decode_never_panics` proptest.
//!
//! The input is read as a run of messages, each a little-endian `u16` length and that many
//! bytes, and fed to one `AudioInput` that records in every format the core encodes. The host's
//! side is played too: an Open is answered with success, and after every message the message's
//! own bytes are pushed as samples, so packets are cut across Format Change PDUs at every
//! `FramesPerPacket` the server names.

use justrdp::audin::{AudioInput, AudioInputConfig, AudioInputEvent};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::audin::ServerPdu::decode(data);
    let mut input = AudioInput::new(AudioInputConfig {
        format_tags: justrdp::audin::ENCODABLE_FORMAT_TAGS.to_vec(),
    })
    .expect("PCM is encodable");
    let mut rest = data;
    while let [lo, hi, tail @ ..] = rest {
        let len = usize::from(u16::from_le_bytes([*lo, *hi])).min(tail.len());
        let (message, next) = tail.split_at(len);
        for event in input.process(message) {
            if let AudioInputEvent::Open { .. } = event {
                let _ = input.open_reply(0);
            }
        }
        let samples: Vec<i16> = message
            .chunks_exact(2)
            .map(|s| i16::from_le_bytes([s[0], s[1]]))
            .collect();
        let _ = input.push(&samples);
        rest = next;
    }
});
