#![no_main]
//! Fuzz the WebSocket client's two parsers of the RD Gateway's bytes (#613). Sibling of
//! `feed_never_panics_and_does_not_depend_on_the_split` and
//! `parse_upgrade_response_never_panics` in `justrdp_tokio::websocket`.
//!
//! `parse_upgrade_response` reads the HTTP answer to the upgrade request. `FrameDecoder::feed`
//! reads frame headers with 7-bit, 16-bit and 64-bit lengths and tracks fragmentation; whatever
//! it reads from the input whole it must read from the same input in pieces.

use justrdp_tokio::fuzzing::{parse_upgrade_response, Control, FrameDecoder, FrameError};
use libfuzzer_sys::fuzz_target;

fn decode(input: &[u8], read_len: usize) -> Result<(Vec<u8>, Vec<Control>), FrameError> {
    let mut decoder = FrameDecoder::new();
    let mut data = Vec::new();
    let mut control = Vec::new();
    for read in input.chunks(read_len) {
        if let Err(error) = decoder.feed(read, &mut data, &mut control) {
            // A refused stream stays refused, whatever follows.
            assert_eq!(decoder.feed(input, &mut data, &mut control), Err(error));
            return Err(error);
        }
    }
    Ok((data, control))
}

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(header_len)) = parse_upgrade_response(data, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") {
        assert!(header_len <= data.len());
    }

    let Some((&read_len, frames)) = data.split_first() else {
        return;
    };
    let whole = decode(frames, frames.len().max(1));
    let split = decode(frames, usize::from(read_len) + 1);
    assert_eq!(whole, split);
});
