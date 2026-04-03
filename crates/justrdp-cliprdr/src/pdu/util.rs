#![forbid(unsafe_code)]

//! Shared UTF-16LE encoding/decoding helpers for fixed-size wire buffers.

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{DecodeError, DecodeResult};

/// Encode `s` as UTF-16LE into `buf`, null-terminated, truncating if needed.
///
/// `buf` must be an even number of bytes (>= 2). The last two bytes are
/// reserved for the null terminator. The buffer is zeroed before writing.
pub(super) fn encode_utf16le_fixed(s: &str, buf: &mut [u8]) {
    debug_assert!(buf.len() >= 2 && buf.len() % 2 == 0);
    // Zero the entire buffer first. This guarantees the null terminator (last 2 bytes)
    // even when the name exactly fills the data region, without a separate write.
    buf.fill(0);
    let max_data_bytes = buf.len() - 2; // bytes available for encoded code units
    let mut offset = 0;
    for code_unit in s.encode_utf16() {
        if offset + 2 > max_data_bytes {
            break;
        }
        buf[offset] = code_unit as u8;
        buf[offset + 1] = (code_unit >> 8) as u8;
        offset += 2;
    }
    // Null terminator is already zero from fill(0).
}

/// Decode a null-terminated UTF-16LE string from a byte slice.
pub(super) fn decode_utf16le_null_terminated(
    bytes: &[u8],
    context: &'static str,
    field: &'static str,
) -> DecodeResult<String> {
    let code_units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&cu| cu != 0)
        .collect();
    String::from_utf16(&code_units).map_err(|_| DecodeError::invalid_value(context, field))
}
