#![forbid(unsafe_code)]

//! NDR/RPCE serialization primitives for the MS-RDPESC smartcard protocol.
//!
//! Implements:
//! - RPCE Type Serialization Version 1 envelope (MS-RPCE 2.2.6.1, 2.2.6.2)
//! - NDR unique pointers, conformant byte arrays, NDR strings
//! - REDIR_SCARDCONTEXT / REDIR_SCARDHANDLE (MS-RDPESC 2.2.1.1, 2.2.1.2)

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{DecodeError, DecodeResult, EncodeResult, ReadCursor, WriteCursor};

// ── Constants ──

/// RPCE Common Type Header size (MS-RPCE 2.2.6.1)
const RPCE_COMMON_HEADER_SIZE: usize = 8;

/// RPCE Private Header size (MS-RPCE 2.2.6.2)
const RPCE_PRIVATE_HEADER_SIZE: usize = 8;

/// Total RPCE envelope size
pub const RPCE_HEADER_SIZE: usize = RPCE_COMMON_HEADER_SIZE + RPCE_PRIVATE_HEADER_SIZE;

/// Non-null referent ID for NDR unique pointers.
pub const NDR_PTR_NON_NULL: u32 = 0x0002_0000;

/// Maximum allowed cbContext / cbHandle length.
const MAX_CONTEXT_HANDLE_LEN: u32 = 16;

/// Maximum allowed NDR string element count.
const MAX_NDR_STRING_ELEMENTS: u32 = 65536;

// ── RPCE Envelope ──

/// Encode RPCE Type Serialization Version 1 header (Common + Private).
///
/// `ndr_body_len` is the length of the NDR data that follows the header.
/// The ObjectBufferLength in the private header is `ndr_body_len` rounded up to 8-byte alignment.
pub fn encode_rpce_header(dst: &mut WriteCursor<'_>, ndr_body_len: usize) -> EncodeResult<()> {
    // Common Type Header (MS-RPCE 2.2.6.1)
    dst.write_u8(0x01, "Version")?;
    dst.write_u8(0x10, "Endianness")?;
    dst.write_u16_le(0x0008, "CommonHeaderLength")?;
    dst.write_u32_le(0xCCCC_CCCC, "Filler")?;

    // Private Header (MS-RPCE 2.2.6.2)
    let padded_len = align8(ndr_body_len);
    dst.write_u32_le(padded_len as u32, "ObjectBufferLength")?;
    dst.write_u32_le(0x0000_0000, "Filler2")?;

    Ok(())
}

/// Decode RPCE Type Serialization Version 1 header.
///
/// Returns `ObjectBufferLength` from the private header.
pub fn decode_rpce_header(src: &mut ReadCursor<'_>) -> DecodeResult<u32> {
    // Common Type Header (MS-RPCE 2.2.6.1)
    let version = src.read_u8("Version")?;
    if version != 0x01 {
        return Err(DecodeError::invalid_value("RpceHeader", "Version"));
    }

    let endianness = src.read_u8("Endianness")?;
    if endianness != 0x10 {
        return Err(DecodeError::invalid_value("RpceHeader", "Endianness"));
    }

    let common_header_len = src.read_u16_le("CommonHeaderLength")?;
    if common_header_len != 0x0008 {
        return Err(DecodeError::invalid_value("RpceHeader", "CommonHeaderLength"));
    }

    // Filler - ignore on decode
    let _filler = src.read_u32_le("Filler")?;

    // Private Header (MS-RPCE 2.2.6.2)
    let object_buffer_length = src.read_u32_le("ObjectBufferLength")?;
    let _filler2 = src.read_u32_le("Filler2")?;

    Ok(object_buffer_length)
}

// ── NDR Unique Pointer ──

/// Encode a unique pointer referent ID.
///
/// Non-null pointers use `NDR_PTR_NON_NULL`, null pointers use `0`.
pub fn encode_ptr_id(dst: &mut WriteCursor<'_>, is_null: bool) -> EncodeResult<()> {
    let id = if is_null { 0u32 } else { NDR_PTR_NON_NULL };
    dst.write_u32_le(id, "ReferentId")?;
    Ok(())
}

/// Decode a unique pointer referent ID.
///
/// Returns `true` if the pointer is non-null (referent ID != 0).
pub fn decode_ptr_id(src: &mut ReadCursor<'_>) -> DecodeResult<bool> {
    let id = src.read_u32_le("ReferentId")?;
    Ok(id != 0)
}

// ── Conformant Byte Array ──

/// Encode a conformant byte array (deferred section).
///
/// Writes MaxCount (u32) followed by `data.len()` bytes.
pub fn encode_conformant_bytes(dst: &mut WriteCursor<'_>, data: &[u8]) -> EncodeResult<()> {
    dst.write_u32_le(data.len() as u32, "MaxCount")?;
    dst.write_slice(data, "Data")?;
    Ok(())
}

/// Decode a conformant byte array (deferred section).
///
/// `max_len` is the caller-provided upper bound on the byte count.
pub fn decode_conformant_bytes(src: &mut ReadCursor<'_>, max_len: usize) -> DecodeResult<Vec<u8>> {
    let max_count = src.read_u32_le("MaxCount")? as usize;
    if max_count > max_len {
        return Err(DecodeError::invalid_value("ConformantBytes", "MaxCount"));
    }
    let data = src.read_slice(max_count, "Data")?;
    Ok(data.to_vec())
}

// ── NDR String (ASCII) ──

/// Encode an NDR null-terminated ASCII string (deferred section).
///
/// Writes MaxCount, Offset (0), ActualCount, then the string bytes including null terminator.
pub fn encode_ndr_string_a(dst: &mut WriteCursor<'_>, s: &str) -> EncodeResult<()> {
    let actual_count = s.len() + 1; // include null terminator
    let max_count = actual_count;

    dst.write_u32_le(max_count as u32, "MaxCount")?;
    dst.write_u32_le(0, "Offset")?;
    dst.write_u32_le(actual_count as u32, "ActualCount")?;
    dst.write_slice(s.as_bytes(), "StringData")?;
    dst.write_u8(0, "NullTerminator")?;

    Ok(())
}

/// Decode an NDR null-terminated ASCII string (deferred section).
pub fn decode_ndr_string_a(src: &mut ReadCursor<'_>) -> DecodeResult<String> {
    let _max_count = src.read_u32_le("MaxCount")?;
    let _offset = src.read_u32_le("Offset")?;
    let actual_count = src.read_u32_le("ActualCount")?;

    if actual_count > MAX_NDR_STRING_ELEMENTS {
        return Err(DecodeError::invalid_value("NdrStringA", "ActualCount"));
    }

    let data = src.read_slice(actual_count as usize, "StringData")?;

    // Strip trailing null terminator(s)
    let end = data
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(data.len());

    // ASCII bytes are valid UTF-8 for printable chars; use lossy conversion for safety
    let s = String::from_utf8_lossy(&data[..end]).into_owned();
    Ok(s)
}

// ── NDR String (UTF-16LE) ──

/// Encode an NDR null-terminated UTF-16LE string (deferred section).
///
/// Each element is 2 bytes (u16 LE). ActualCount includes the null terminator.
pub fn encode_ndr_string_w(dst: &mut WriteCursor<'_>, s: &str) -> EncodeResult<()> {
    let utf16: Vec<u16> = s.encode_utf16().chain(core::iter::once(0u16)).collect();
    let actual_count = utf16.len() as u32;
    let max_count = actual_count;

    dst.write_u32_le(max_count, "MaxCount")?;
    dst.write_u32_le(0, "Offset")?;
    dst.write_u32_le(actual_count, "ActualCount")?;

    for &unit in &utf16 {
        dst.write_u16_le(unit, "Utf16Unit")?;
    }

    Ok(())
}

/// Decode an NDR null-terminated UTF-16LE string (deferred section).
pub fn decode_ndr_string_w(src: &mut ReadCursor<'_>) -> DecodeResult<String> {
    let _max_count = src.read_u32_le("MaxCount")?;
    let _offset = src.read_u32_le("Offset")?;
    let actual_count = src.read_u32_le("ActualCount")?;

    if actual_count > MAX_NDR_STRING_ELEMENTS {
        return Err(DecodeError::invalid_value("NdrStringW", "ActualCount"));
    }

    let byte_count = (actual_count as usize) * 2;
    let data = src.read_slice(byte_count, "Utf16Data")?;

    // Convert UTF-16LE pairs to u16, then decode
    let iter = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]));

    let s: String = core::char::decode_utf16(iter)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();

    // Trim trailing null(s)
    let s: String = s.trim_end_matches('\0').into();
    Ok(s)
}

// ── REDIR_SCARDCONTEXT (MS-RDPESC 2.2.1.1) ──

/// Encode REDIR_SCARDCONTEXT inline part.
///
/// Layout: cbContext (u32) + unique pointer referent ID
pub fn encode_scard_context_inline(dst: &mut WriteCursor<'_>, context: &[u8]) -> EncodeResult<()> {
    let cb = context.len() as u32;
    dst.write_u32_le(cb, "cbContext")?;
    encode_ptr_id(dst, context.is_empty())?;
    Ok(())
}

/// Decode REDIR_SCARDCONTEXT inline part.
///
/// Returns `(cb_context, has_data)`.
pub fn decode_scard_context_inline(src: &mut ReadCursor<'_>) -> DecodeResult<(u32, bool)> {
    let cb_context = src.read_u32_le("cbContext")?;
    if cb_context > MAX_CONTEXT_HANDLE_LEN {
        return Err(DecodeError::invalid_value("ScardContext", "cbContext"));
    }
    let has_data = decode_ptr_id(src)?;
    Ok((cb_context, has_data))
}

/// Encode REDIR_SCARDCONTEXT deferred part.
///
/// Writes the conformant byte array for the context data.
pub fn encode_scard_context_deferred(dst: &mut WriteCursor<'_>, context: &[u8]) -> EncodeResult<()> {
    if !context.is_empty() {
        encode_conformant_bytes(dst, context)?;
    }
    Ok(())
}

/// Decode REDIR_SCARDCONTEXT deferred part.
///
/// `cb_context` is the length from the inline part.
pub fn decode_scard_context_deferred(src: &mut ReadCursor<'_>, cb_context: u32) -> DecodeResult<Vec<u8>> {
    decode_conformant_bytes(src, cb_context as usize)
}

// ── REDIR_SCARDHANDLE (MS-RDPESC 2.2.1.2) ──

/// Encode REDIR_SCARDHANDLE inline part.
///
/// Layout: context inline + cbHandle (u32) + handle pointer referent ID
pub fn encode_scard_handle_inline(
    dst: &mut WriteCursor<'_>,
    context: &[u8],
    handle: &[u8],
) -> EncodeResult<()> {
    encode_scard_context_inline(dst, context)?;
    let cb = handle.len() as u32;
    dst.write_u32_le(cb, "cbHandle")?;
    encode_ptr_id(dst, handle.is_empty())?;
    Ok(())
}

/// Decode REDIR_SCARDHANDLE inline part.
///
/// Returns `(cb_ctx, has_ctx, cb_handle, has_handle)`.
pub fn decode_scard_handle_inline(
    src: &mut ReadCursor<'_>,
) -> DecodeResult<(u32, bool, u32, bool)> {
    let (cb_ctx, has_ctx) = decode_scard_context_inline(src)?;
    let cb_handle = src.read_u32_le("cbHandle")?;
    if cb_handle > MAX_CONTEXT_HANDLE_LEN {
        return Err(DecodeError::invalid_value("ScardHandle", "cbHandle"));
    }
    let has_handle = decode_ptr_id(src)?;
    Ok((cb_ctx, has_ctx, cb_handle, has_handle))
}

/// Encode REDIR_SCARDHANDLE deferred part.
///
/// Writes context deferred + handle deferred.
pub fn encode_scard_handle_deferred(
    dst: &mut WriteCursor<'_>,
    context: &[u8],
    handle: &[u8],
) -> EncodeResult<()> {
    encode_scard_context_deferred(dst, context)?;
    if !handle.is_empty() {
        encode_conformant_bytes(dst, handle)?;
    }
    Ok(())
}

/// Decode REDIR_SCARDHANDLE deferred part.
///
/// Returns `(context_data, handle_data)`.
pub fn decode_scard_handle_deferred(
    src: &mut ReadCursor<'_>,
    cb_ctx: u32,
    cb_handle: u32,
) -> DecodeResult<(Vec<u8>, Vec<u8>)> {
    let ctx = decode_conformant_bytes(src, cb_ctx as usize)?;
    let handle = decode_conformant_bytes(src, cb_handle as usize)?;
    Ok((ctx, handle))
}

// ── Helpers ──

/// Round `n` up to the next multiple of 8.
#[inline]
fn align8(n: usize) -> usize {
    (n + 7) & !7
}

// ── Tests ──

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec;

    /// Helper: encode into a buffer and return the used portion.
    fn encode_to_vec(f: impl FnOnce(&mut WriteCursor<'_>) -> EncodeResult<()>) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let written = {
            let mut cursor = WriteCursor::new(&mut buf);
            f(&mut cursor).expect("encode should succeed");
            cursor.pos()
        };
        buf.truncate(written);
        buf
    }

    #[test]
    fn rpce_header_roundtrip() {
        let ndr_body_len = 20usize;
        let encoded = encode_to_vec(|dst| encode_rpce_header(dst, ndr_body_len));
        assert_eq!(encoded.len(), RPCE_HEADER_SIZE);

        let mut cursor = ReadCursor::new(&encoded);
        let obj_len = decode_rpce_header(&mut cursor).expect("decode should succeed");
        // 20 rounded up to 8-byte boundary = 24
        assert_eq!(obj_len, 24);
    }

    #[test]
    fn rpce_header_known_bytes() {
        // EstablishContext_Call common header bytes from spec
        let expected_common = [0x01, 0x10, 0x08, 0x00, 0xCC, 0xCC, 0xCC, 0xCC];
        let encoded = encode_to_vec(|dst| encode_rpce_header(dst, 4));
        assert_eq!(&encoded[..8], &expected_common);
    }

    #[test]
    fn unique_pointer_non_null_roundtrip() {
        let encoded = encode_to_vec(|dst| encode_ptr_id(dst, false));
        assert_eq!(encoded.len(), 4);

        let mut cursor = ReadCursor::new(&encoded);
        let is_non_null = decode_ptr_id(&mut cursor).expect("decode should succeed");
        assert!(is_non_null);
    }

    #[test]
    fn unique_pointer_null_roundtrip() {
        let encoded = encode_to_vec(|dst| encode_ptr_id(dst, true));

        let mut cursor = ReadCursor::new(&encoded);
        let is_non_null = decode_ptr_id(&mut cursor).expect("decode should succeed");
        assert!(!is_non_null);
    }

    #[test]
    fn conformant_bytes_roundtrip_empty() {
        let data: &[u8] = &[];
        let encoded = encode_to_vec(|dst| encode_conformant_bytes(dst, data));

        let mut cursor = ReadCursor::new(&encoded);
        let decoded = decode_conformant_bytes(&mut cursor, 256).expect("decode should succeed");
        assert!(decoded.is_empty());
    }

    #[test]
    fn conformant_bytes_roundtrip_non_empty() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = encode_to_vec(|dst| encode_conformant_bytes(dst, &data));
        assert_eq!(encoded.len(), 4 + 4); // MaxCount + data

        let mut cursor = ReadCursor::new(&encoded);
        let decoded = decode_conformant_bytes(&mut cursor, 256).expect("decode should succeed");
        assert_eq!(decoded, data);
    }

    #[test]
    fn conformant_bytes_exceeds_max_len() {
        let data = [0x01; 10];
        let encoded = encode_to_vec(|dst| encode_conformant_bytes(dst, &data));

        let mut cursor = ReadCursor::new(&encoded);
        let result = decode_conformant_bytes(&mut cursor, 5);
        assert!(result.is_err());
    }

    #[test]
    fn ndr_string_a_roundtrip() {
        let s = "Hello";
        let encoded = encode_to_vec(|dst| encode_ndr_string_a(dst, s));
        // MaxCount(4) + Offset(4) + ActualCount(4) + 5 chars + null = 18
        assert_eq!(encoded.len(), 4 + 4 + 4 + 6);

        let mut cursor = ReadCursor::new(&encoded);
        let decoded = decode_ndr_string_a(&mut cursor).expect("decode should succeed");
        assert_eq!(decoded, "Hello");
    }

    #[test]
    fn ndr_string_a_empty() {
        let s = "";
        let encoded = encode_to_vec(|dst| encode_ndr_string_a(dst, s));

        let mut cursor = ReadCursor::new(&encoded);
        let decoded = decode_ndr_string_a(&mut cursor).expect("decode should succeed");
        assert_eq!(decoded, "");
    }

    #[test]
    fn ndr_string_w_roundtrip() {
        let s = "Test";
        let encoded = encode_to_vec(|dst| encode_ndr_string_w(dst, s));
        // MaxCount(4) + Offset(4) + ActualCount(4) + (4+1)*2 = 22
        assert_eq!(encoded.len(), 4 + 4 + 4 + 10);

        let mut cursor = ReadCursor::new(&encoded);
        let decoded = decode_ndr_string_w(&mut cursor).expect("decode should succeed");
        assert_eq!(decoded, "Test");
    }

    #[test]
    fn ndr_string_w_empty() {
        let s = "";
        let encoded = encode_to_vec(|dst| encode_ndr_string_w(dst, s));

        let mut cursor = ReadCursor::new(&encoded);
        let decoded = decode_ndr_string_w(&mut cursor).expect("decode should succeed");
        assert_eq!(decoded, "");
    }

    #[test]
    fn scard_context_roundtrip() {
        let ctx = [0x01, 0x02, 0x03, 0x04];
        let encoded = encode_to_vec(|dst| {
            encode_scard_context_inline(dst, &ctx)?;
            encode_scard_context_deferred(dst, &ctx)?;
            Ok(())
        });

        let mut cursor = ReadCursor::new(&encoded);
        let (cb, has_data) = decode_scard_context_inline(&mut cursor).expect("inline decode");
        assert_eq!(cb, 4);
        assert!(has_data);
        let data = decode_scard_context_deferred(&mut cursor, cb).expect("deferred decode");
        assert_eq!(data, ctx);
    }

    #[test]
    fn scard_context_empty() {
        let ctx: &[u8] = &[];
        let encoded = encode_to_vec(|dst| {
            encode_scard_context_inline(dst, ctx)?;
            encode_scard_context_deferred(dst, ctx)?;
            Ok(())
        });

        let mut cursor = ReadCursor::new(&encoded);
        let (cb, has_data) = decode_scard_context_inline(&mut cursor).expect("inline decode");
        assert_eq!(cb, 0);
        assert!(!has_data);
    }

    #[test]
    fn scard_handle_roundtrip() {
        let ctx = [0xAA, 0xBB];
        let handle = [0xCC, 0xDD, 0xEE, 0xFF];

        let encoded = encode_to_vec(|dst| {
            encode_scard_handle_inline(dst, &ctx, &handle)?;
            encode_scard_handle_deferred(dst, &ctx, &handle)?;
            Ok(())
        });

        let mut cursor = ReadCursor::new(&encoded);
        let (cb_ctx, has_ctx, cb_handle, has_handle) =
            decode_scard_handle_inline(&mut cursor).expect("inline decode");
        assert_eq!(cb_ctx, 2);
        assert!(has_ctx);
        assert_eq!(cb_handle, 4);
        assert!(has_handle);

        let (ctx_data, handle_data) =
            decode_scard_handle_deferred(&mut cursor, cb_ctx, cb_handle).expect("deferred decode");
        assert_eq!(ctx_data, ctx);
        assert_eq!(handle_data, handle);
    }

    #[test]
    fn scard_context_rejects_oversized() {
        // cbContext > 16 must be rejected
        let mut buf = [0u8; 8];
        {
            let mut w = WriteCursor::new(&mut buf);
            w.write_u32_le(17, "cbContext").unwrap();
            w.write_u32_le(NDR_PTR_NON_NULL, "ptr").unwrap();
        }
        let mut cursor = ReadCursor::new(&buf);
        let result = decode_scard_context_inline(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn rpce_header_invalid_version() {
        let mut buf = [0u8; 16];
        buf[0] = 0x02; // wrong version
        buf[1] = 0x10;
        buf[2] = 0x08;
        // rest zeros
        let mut cursor = ReadCursor::new(&buf);
        assert!(decode_rpce_header(&mut cursor).is_err());
    }

    #[test]
    fn rpce_header_body_len_zero() {
        let encoded = encode_to_vec(|dst| encode_rpce_header(dst, 0));
        let mut cursor = ReadCursor::new(&encoded);
        let obj_len = decode_rpce_header(&mut cursor).unwrap();
        assert_eq!(obj_len, 0);
    }

    #[test]
    fn rpce_header_body_len_alignment() {
        // 1 -> 8, 7 -> 8, 8 -> 8, 9 -> 16
        for (input, expected) in [(1, 8), (7, 8), (8, 8), (9, 16), (16, 16), (17, 24)] {
            let encoded = encode_to_vec(|dst| encode_rpce_header(dst, input));
            let mut cursor = ReadCursor::new(&encoded);
            let obj_len = decode_rpce_header(&mut cursor).unwrap();
            assert_eq!(obj_len, expected as u32, "align8({input}) should be {expected}");
        }
    }
}
