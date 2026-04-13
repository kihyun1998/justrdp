//! Enumeration-channel PDUs (MS-RDPECAM §2.2.2):
//!
//! - [`SelectVersionRequest`]  (§2.2.2.1) — C→S, fixed 2 bytes
//! - [`SelectVersionResponse`] (§2.2.2.2) — S→C, fixed 2 bytes
//! - [`DeviceAddedNotification`]   (§2.2.2.3) — C→S, variable
//! - [`DeviceRemovedNotification`] (§2.2.2.4) — C→S, variable
//!
//! The two `Device*Notification` PDUs carry two differently encoded
//! strings back-to-back with no length prefix: the display name is a
//! null-terminated UTF-16 LE sequence, and the per-device channel name is
//! a null-terminated ANSI string. We preserve both as raw byte/word
//! buffers without the null terminator so the embedder can convert on its
//! own terms, and re-append the terminator during encode.

use alloc::vec::Vec;

use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

use crate::constants::{
    MSG_DEVICE_ADDED_NOTIFICATION, MSG_DEVICE_REMOVED_NOTIFICATION,
    MSG_SELECT_VERSION_REQUEST, MSG_SELECT_VERSION_RESPONSE,
};
use crate::pdu::header::{decode_header, encode_header, expect_message_id, HEADER_SIZE};

// ── Safety caps (checklist §10) ──

/// Hard limit on `VirtualChannelName` length (MS-RDPECAM §2.1).
///
/// The DVC name is null-terminated ANSI and MUST fit in 256 bytes including
/// the terminator, so the name proper is at most 255 bytes.
pub const MAX_VIRTUAL_CHANNEL_NAME: usize = 256;

/// Defensive cap on `DeviceName` length in UTF-16 code units.
///
/// The spec does not define a hard ceiling on the display name, but camera
/// vendors ship human-readable names well under this threshold. 256 code
/// units (512 wire bytes) is generous and bounds decode-time allocation.
pub const MAX_DEVICE_NAME_UTF16: usize = 256;

// ── SelectVersionRequest (§2.2.2.1) ──

/// First message on the enumeration DVC. Carries the client's maximum
/// supported protocol version so the server can pick `min(client, server)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectVersionRequest {
    /// Client-advertised maximum protocol version (1 or 2).
    pub version: u8,
}

impl SelectVersionRequest {
    pub const WIRE_SIZE: usize = HEADER_SIZE;

    pub fn new(version: u8) -> Self {
        Self { version }
    }
}

impl Encode for SelectVersionRequest {
    fn name(&self) -> &'static str {
        "CAM::SelectVersionRequest"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        encode_header(dst, self.version, MSG_SELECT_VERSION_REQUEST, self.name())
    }
}

impl<'de> Decode<'de> for SelectVersionRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::SelectVersionRequest";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_SELECT_VERSION_REQUEST, CTX)?;
        Ok(Self { version })
    }
}

// ── SelectVersionResponse (§2.2.2.2) ──

/// Server reply to [`SelectVersionRequest`]. `version` is the negotiated
/// value, which MUST NOT exceed the client's advertised maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectVersionResponse {
    /// Negotiated protocol version used for the rest of the session.
    pub version: u8,
}

impl SelectVersionResponse {
    pub const WIRE_SIZE: usize = HEADER_SIZE;

    pub fn new(version: u8) -> Self {
        Self { version }
    }
}

impl Encode for SelectVersionResponse {
    fn name(&self) -> &'static str {
        "CAM::SelectVersionResponse"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        encode_header(dst, self.version, MSG_SELECT_VERSION_RESPONSE, self.name())
    }
}

impl<'de> Decode<'de> for SelectVersionResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::SelectVersionResponse";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_SELECT_VERSION_RESPONSE, CTX)?;
        Ok(Self { version })
    }
}

// ── String helpers ──

/// Parses a null-terminated UTF-16 LE string starting at the cursor.
///
/// Returns the decoded code units without the trailing `0x0000`. Fails if
/// the buffer does not contain a well-aligned terminator, if the remaining
/// length is odd, or if the string (excluding the terminator) exceeds
/// `MAX_DEVICE_NAME_UTF16` code units.
fn read_utf16_null_terminated(
    src: &mut ReadCursor<'_>,
    ctx: &'static str,
    cap: usize,
) -> DecodeResult<Vec<u16>> {
    let mut out = Vec::new();
    loop {
        let unit = src.read_u16_le(ctx)?;
        if unit == 0 {
            return Ok(out);
        }
        if out.len() >= cap {
            return Err(DecodeError::invalid_value(ctx, "DeviceName too long"));
        }
        out.push(unit);
    }
}

/// Writes a UTF-16 LE string followed by a terminating `0x0000`.
fn write_utf16_null_terminated(
    dst: &mut WriteCursor<'_>,
    units: &[u16],
    ctx: &'static str,
) -> EncodeResult<()> {
    for &u in units {
        dst.write_u16_le(u, ctx)?;
    }
    dst.write_u16_le(0, ctx)?;
    Ok(())
}

/// Parses a null-terminated ANSI string and returns the bytes excluding
/// the terminator. Total wire length (including the terminator) MUST NOT
/// exceed [`MAX_VIRTUAL_CHANNEL_NAME`].
fn read_ansi_null_terminated(
    src: &mut ReadCursor<'_>,
    ctx: &'static str,
    cap_including_nul: usize,
) -> DecodeResult<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let b = src.read_u8(ctx)?;
        if b == 0 {
            return Ok(out);
        }
        // out.len() currently excludes the terminator; enforce the cap
        // against the full wire length (out.len() + 1 for the terminator
        // we have not yet encountered).
        if out.len() + 1 >= cap_including_nul {
            return Err(DecodeError::invalid_value(ctx, "VirtualChannelName too long"));
        }
        out.push(b);
    }
}

/// Writes an ANSI byte string followed by a `0x00` terminator.
fn write_ansi_null_terminated(
    dst: &mut WriteCursor<'_>,
    bytes: &[u8],
    ctx: &'static str,
) -> EncodeResult<()> {
    for &b in bytes {
        dst.write_u8(b, ctx)?;
    }
    dst.write_u8(0, ctx)?;
    Ok(())
}

// ── DeviceAddedNotification (§2.2.2.3) ──

/// Advertises a newly attached camera device on the enumeration channel.
///
/// `device_name` is a human-readable UTF-16 code-unit sequence (no
/// terminator). `virtual_channel_name` is the raw ANSI byte string the
/// client will create a per-device DVC with; it excludes the null
/// terminator. Both strings are written back with terminators during encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAddedNotification {
    pub version: u8,
    /// UTF-16 LE code units (without terminator).
    pub device_name: Vec<u16>,
    /// ANSI bytes (without terminator).
    pub virtual_channel_name: Vec<u8>,
}

impl DeviceAddedNotification {
    fn wire_size(&self) -> usize {
        HEADER_SIZE
            + (self.device_name.len() + 1) * 2
            + self.virtual_channel_name.len()
            + 1
    }
}

impl Encode for DeviceAddedNotification {
    fn name(&self) -> &'static str {
        "CAM::DeviceAddedNotification"
    }

    fn size(&self) -> usize {
        self.wire_size()
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::DeviceAddedNotification";
        // Enforce the same caps on encode as on decode, so a buggy caller
        // can't produce a wire message the peer would reject at parse time.
        if self.device_name.len() > MAX_DEVICE_NAME_UTF16 {
            return Err(justrdp_core::EncodeError::invalid_value(
                CTX,
                "device_name too long",
            ));
        }
        if self.virtual_channel_name.len() + 1 > MAX_VIRTUAL_CHANNEL_NAME {
            return Err(justrdp_core::EncodeError::invalid_value(
                CTX,
                "virtual_channel_name too long",
            ));
        }
        encode_header(dst, self.version, MSG_DEVICE_ADDED_NOTIFICATION, CTX)?;
        write_utf16_null_terminated(dst, &self.device_name, CTX)?;
        write_ansi_null_terminated(dst, &self.virtual_channel_name, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for DeviceAddedNotification {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::DeviceAddedNotification";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_DEVICE_ADDED_NOTIFICATION, CTX)?;
        let device_name = read_utf16_null_terminated(src, CTX, MAX_DEVICE_NAME_UTF16)?;
        let virtual_channel_name = read_ansi_null_terminated(src, CTX, MAX_VIRTUAL_CHANNEL_NAME)?;
        Ok(Self {
            version,
            device_name,
            virtual_channel_name,
        })
    }
}

// ── DeviceRemovedNotification (§2.2.2.4) ──

/// Signals that the camera identified by `virtual_channel_name` is gone.
/// The client MUST close the corresponding per-device DVC after sending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRemovedNotification {
    pub version: u8,
    /// ANSI bytes (without terminator).
    pub virtual_channel_name: Vec<u8>,
}

impl DeviceRemovedNotification {
    fn wire_size(&self) -> usize {
        HEADER_SIZE + self.virtual_channel_name.len() + 1
    }
}

impl Encode for DeviceRemovedNotification {
    fn name(&self) -> &'static str {
        "CAM::DeviceRemovedNotification"
    }

    fn size(&self) -> usize {
        self.wire_size()
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::DeviceRemovedNotification";
        if self.virtual_channel_name.len() + 1 > MAX_VIRTUAL_CHANNEL_NAME {
            return Err(justrdp_core::EncodeError::invalid_value(
                CTX,
                "virtual_channel_name too long",
            ));
        }
        encode_header(dst, self.version, MSG_DEVICE_REMOVED_NOTIFICATION, CTX)?;
        write_ansi_null_terminated(dst, &self.virtual_channel_name, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for DeviceRemovedNotification {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::DeviceRemovedNotification";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_DEVICE_REMOVED_NOTIFICATION, CTX)?;
        let virtual_channel_name = read_ansi_null_terminated(src, CTX, MAX_VIRTUAL_CHANNEL_NAME)?;
        Ok(Self {
            version,
            virtual_channel_name,
        })
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{VERSION_1, VERSION_2};

    fn encode<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf: Vec<u8> = alloc::vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        assert_eq!(w.pos(), pdu.size());
        buf
    }

    // ── SelectVersionRequest / Response ──

    #[test]
    fn select_version_request_spec_sample() {
        // Spec §4.1.1 test vector: version 2 request.
        let pdu = SelectVersionRequest::new(VERSION_2);
        assert_eq!(encode(&pdu), [0x02, 0x03]);
        let mut r = ReadCursor::new(&[0x02u8, 0x03]);
        assert_eq!(SelectVersionRequest::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn select_version_response_spec_sample() {
        // Spec §4.1.2 test vector: version 2 response.
        let pdu = SelectVersionResponse::new(VERSION_2);
        assert_eq!(encode(&pdu), [0x02, 0x04]);
        let mut r = ReadCursor::new(&[0x02u8, 0x04]);
        assert_eq!(SelectVersionResponse::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn select_version_roundtrip_v1() {
        let pdu = SelectVersionRequest::new(VERSION_1);
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x01, 0x03]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(SelectVersionRequest::decode(&mut r).unwrap(), pdu);
    }

    // ── DeviceAddedNotification ──

    /// Spec §4.2.1 test vector — "Mock Camera 1" + "RDCamera_Device_0".
    fn spec_device_added_bytes() -> Vec<u8> {
        let mut v: Vec<u8> = alloc::vec![];
        // Header
        v.extend_from_slice(&[0x02, 0x05]);
        // UTF-16 "Mock Camera 1\0"
        for c in "Mock Camera 1".chars() {
            v.extend_from_slice(&(c as u16).to_le_bytes());
        }
        v.extend_from_slice(&[0x00, 0x00]);
        // ANSI "RDCamera_Device_0\0"
        v.extend_from_slice(b"RDCamera_Device_0\0");
        v
    }

    #[test]
    fn device_added_spec_sample_decode() {
        let bytes = spec_device_added_bytes();
        let mut r = ReadCursor::new(&bytes);
        let pdu = DeviceAddedNotification::decode(&mut r).unwrap();
        assert_eq!(pdu.version, VERSION_2);
        let name: Vec<u16> = "Mock Camera 1".chars().map(|c| c as u16).collect();
        assert_eq!(pdu.device_name, name);
        assert_eq!(pdu.virtual_channel_name, b"RDCamera_Device_0".to_vec());
    }

    #[test]
    fn device_added_spec_sample_roundtrip() {
        let bytes = spec_device_added_bytes();
        let mut r = ReadCursor::new(&bytes);
        let pdu = DeviceAddedNotification::decode(&mut r).unwrap();
        assert_eq!(encode(&pdu), bytes);
    }

    #[test]
    fn device_added_empty_names_roundtrip() {
        // Both strings empty: wire form = header + "\0\0" + "\0" = 5 bytes.
        let pdu = DeviceAddedNotification {
            version: VERSION_1,
            device_name: Vec::new(),
            virtual_channel_name: Vec::new(),
        };
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x01, 0x05, 0x00, 0x00, 0x00]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(DeviceAddedNotification::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn device_added_rejects_channel_name_at_limit() {
        // 256 non-null bytes → total with terminator = 257 → rejected.
        let too_long: Vec<u8> = alloc::vec![b'A'; MAX_VIRTUAL_CHANNEL_NAME];
        let pdu = DeviceAddedNotification {
            version: VERSION_2,
            device_name: Vec::new(),
            virtual_channel_name: too_long,
        };
        let mut buf: Vec<u8> = alloc::vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        assert!(pdu.encode(&mut w).is_err());
    }

    #[test]
    fn device_added_accepts_channel_name_at_exact_limit() {
        // 255 bytes + 1 terminator = 256 total → allowed.
        let name: Vec<u8> = alloc::vec![b'A'; MAX_VIRTUAL_CHANNEL_NAME - 1];
        let pdu = DeviceAddedNotification {
            version: VERSION_2,
            device_name: Vec::new(),
            virtual_channel_name: name,
        };
        let bytes = encode(&pdu);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(DeviceAddedNotification::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn device_added_rejects_device_name_over_cap() {
        // decode path: construct wire bytes with MAX_DEVICE_NAME_UTF16+1 code units
        let mut bytes: Vec<u8> = alloc::vec![0x02, 0x05];
        for _ in 0..=MAX_DEVICE_NAME_UTF16 {
            bytes.extend_from_slice(&0x0041u16.to_le_bytes());
        }
        bytes.extend_from_slice(&[0x00, 0x00]);
        bytes.extend_from_slice(b"\0");
        let mut r = ReadCursor::new(&bytes);
        assert!(DeviceAddedNotification::decode(&mut r).is_err());
    }

    // ── DeviceRemovedNotification ──

    #[test]
    fn device_removed_roundtrip() {
        let pdu = DeviceRemovedNotification {
            version: VERSION_2,
            virtual_channel_name: b"RDCamera_Device_0".to_vec(),
        };
        let bytes = encode(&pdu);
        let mut expected: Vec<u8> = alloc::vec![0x02, 0x06];
        expected.extend_from_slice(b"RDCamera_Device_0\0");
        assert_eq!(bytes, expected);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(DeviceRemovedNotification::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn device_removed_empty_name_roundtrip() {
        let pdu = DeviceRemovedNotification {
            version: VERSION_1,
            virtual_channel_name: Vec::new(),
        };
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x01, 0x06, 0x00]);
    }

    #[test]
    fn device_removed_rejects_missing_terminator() {
        // Header + 3 non-null bytes, no 0x00: read_u8 will hit end-of-buffer.
        let bytes = [0x02u8, 0x06, b'A', b'B', b'C'];
        let mut r = ReadCursor::new(&bytes);
        assert!(DeviceRemovedNotification::decode(&mut r).is_err());
    }

    // ── Common: bad headers ──

    #[test]
    fn device_added_rejects_wrong_message_id() {
        let bytes = [0x02u8, 0x06, 0x00, 0x00, 0x00];
        let mut r = ReadCursor::new(&bytes);
        assert!(DeviceAddedNotification::decode(&mut r).is_err());
    }

    #[test]
    fn device_removed_rejects_wrong_message_id() {
        let bytes = [0x02u8, 0x05, 0x00];
        let mut r = ReadCursor::new(&bytes);
        assert!(DeviceRemovedNotification::decode(&mut r).is_err());
    }
}
