#![no_main]
//! Fuzz the audio output channel (#386): the `[MS-RDPEA]` PDU parser and the helper that
//! drives it. Sibling of rdpsnd's `decode_never_panics` proptest.
//!
//! `ServerPdu::decode` reads a `SNDPROLOG` whose `BodySize` must cover the message, except on a
//! WaveInfo PDU, where it announces the next message's length instead. The input is read as a
//! run of messages, each a little-endian `u16` length and that many bytes, and fed to one
//! `AudioOutput` that takes every format the core decodes and advertises volume control, so a
//! format list can precede the WaveInfo, Wave and Wave2 PDUs that index it, and every decoder
//! and the Volume path are reached.

use justrdp::rdpsnd::{AudioOutput, AudioOutputConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::rdpsnd::ServerPdu::decode(data);
    let mut output = AudioOutput::new(AudioOutputConfig {
        format_tags: justrdp::rdpsnd::DECODABLE_FORMAT_TAGS.to_vec(),
        volume: Some(0xFFFF_FFFF),
        ..AudioOutputConfig::default()
    })
    .expect("PCM is decodable");
    let mut rest = data;
    while let [lo, hi, tail @ ..] = rest {
        let len = usize::from(u16::from_le_bytes([*lo, *hi])).min(tail.len());
        let (message, next) = tail.split_at(len);
        let _ = output.process(message);
        rest = next;
    }
});
