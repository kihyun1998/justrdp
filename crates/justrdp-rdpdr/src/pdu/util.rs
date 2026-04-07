#![forbid(unsafe_code)]

//! Shared encoding/decoding utilities.

extern crate alloc;

use alloc::string::String;

/// Decode UTF-16LE bytes (possibly null-terminated) into a String.
pub(crate) fn decode_utf16le(data: &[u8]) -> String {
    let len = data.len() & !1;
    let iter = data[..len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]));
    let s: String = core::char::decode_utf16(iter)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    s.trim_end_matches('\0').into()
}
