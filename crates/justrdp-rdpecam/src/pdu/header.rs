//! `SHARED_MSG_HEADER` (MS-RDPECAM §2.2.1) -- the 2-byte preamble that
//! precedes every PDU on both the enumeration and per-device DVCs.
//!
//! | Offset | Size | Field     |
//! |-------:|-----:|-----------|
//! |      0 |    1 | `Version` |
//! |      1 |    1 | `MessageId` |
//!
//! This module exposes free helpers rather than a dedicated struct: the
//! header is so small that every PDU inlines it into its own `encode`/
//! `decode` impl, and having to construct a throwaway wrapper type just
//! to read two bytes is pure ceremony.

use justrdp_core::{DecodeError, DecodeResult, EncodeResult, ReadCursor, WriteCursor};

use crate::constants::{VERSION_1, VERSION_2};

/// Wire size of `SHARED_MSG_HEADER`.
pub const HEADER_SIZE: usize = 2;

/// Writes the 2-byte `SHARED_MSG_HEADER`.
///
/// `version` MUST be either [`VERSION_1`] or [`VERSION_2`]; callers that
/// have negotiated a concrete version are expected to pass it unchanged.
/// The function does not validate `message_id` -- that is the PDU's job.
pub fn encode_header(
    dst: &mut WriteCursor<'_>,
    version: u8,
    message_id: u8,
    ctx: &'static str,
) -> EncodeResult<()> {
    dst.write_u8(version, ctx)?;
    dst.write_u8(message_id, ctx)?;
    Ok(())
}

/// Reads and validates the 2-byte `SHARED_MSG_HEADER`.
///
/// Returns `(version, message_id)` on success. Fails with
/// `DecodeError::invalid_value("Version")` if the protocol version byte is
/// outside {1, 2}. The caller is responsible for:
///
/// * Matching `message_id` against the PDU it expects;
/// * Refusing v2-only message ids when the negotiated version is 1
///   (use [`crate::constants::is_v2_only`]).
pub fn decode_header(
    src: &mut ReadCursor<'_>,
    ctx: &'static str,
) -> DecodeResult<(u8, u8)> {
    let version = src.read_u8(ctx)?;
    let message_id = src.read_u8(ctx)?;
    if version != VERSION_1 && version != VERSION_2 {
        return Err(DecodeError::invalid_value(ctx, "Version"));
    }
    Ok((version, message_id))
}

/// Validates `message_id` against an expected value, producing a
/// clean `invalid_value("MessageId")` error otherwise.
pub fn expect_message_id(
    actual: u8,
    expected: u8,
    ctx: &'static str,
) -> DecodeResult<()> {
    if actual != expected {
        return Err(DecodeError::invalid_value(ctx, "MessageId"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn roundtrip_v1_header() {
        let mut buf: Vec<u8> = alloc::vec![0u8; HEADER_SIZE];
        let mut w = WriteCursor::new(&mut buf);
        encode_header(&mut w, VERSION_1, 0x0A, "test").unwrap();
        assert_eq!(buf, [0x01, 0x0A]);
        let mut r = ReadCursor::new(&buf);
        let (v, id) = decode_header(&mut r, "test").unwrap();
        assert_eq!((v, id), (VERSION_1, 0x0A));
    }

    #[test]
    fn roundtrip_v2_header() {
        let mut buf: Vec<u8> = alloc::vec![0u8; HEADER_SIZE];
        let mut w = WriteCursor::new(&mut buf);
        encode_header(&mut w, VERSION_2, 0x18, "test").unwrap();
        assert_eq!(buf, [0x02, 0x18]);
        let mut r = ReadCursor::new(&buf);
        let (v, id) = decode_header(&mut r, "test").unwrap();
        assert_eq!((v, id), (VERSION_2, 0x18));
    }

    #[test]
    fn rejects_version_zero() {
        let buf = [0x00u8, 0x03];
        let mut r = ReadCursor::new(&buf);
        assert!(decode_header(&mut r, "test").is_err());
    }

    #[test]
    fn rejects_version_three() {
        let buf = [0x03u8, 0x03];
        let mut r = ReadCursor::new(&buf);
        assert!(decode_header(&mut r, "test").is_err());
    }

    #[test]
    fn expect_message_id_matches_and_mismatches() {
        assert!(expect_message_id(0x05, 0x05, "t").is_ok());
        assert!(expect_message_id(0x05, 0x06, "t").is_err());
    }
}
