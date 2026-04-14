//! MS-RDPEPNP §2.2.2.1 — FileRedirectorChannel message headers.
//!
//! Unlike PNPDR (which carries a single 8-byte `PNP_INFO_HEADER` with a
//! total `Size` field), the FileRedirectorChannel sub-protocol splits
//! its framing across two asymmetric headers:
//!
//! * [`ServerIoHeader`] (8 bytes, S→C) — `RequestId` (24-bit LE) +
//!   `UnusedBits` (u8) + `FunctionId` (u32 LE).
//! * [`ClientIoHeader`] (4 bytes, C→S) — `RequestId` (24-bit LE) +
//!   `PacketType` (u8).
//!
//! Neither header carries a size field; the DVC layer is expected to
//! frame the entire message for us before decoding.

use justrdp_core::{DecodeError, DecodeResult, EncodeError, EncodeResult, ReadCursor, WriteCursor};

use crate::constants::{
    CLIENT_IO_HEADER_SIZE, MAX_REQUEST_ID, SERVER_IO_HEADER_SIZE,
};

// ── u24 little-endian helpers ──

pub(crate) fn write_u24_le(
    dst: &mut WriteCursor<'_>,
    value: u32,
    ctx: &'static str,
) -> EncodeResult<()> {
    if value > MAX_REQUEST_ID {
        return Err(EncodeError::invalid_value(ctx, "RequestId > 24 bits"));
    }
    let bytes = [
        (value & 0xFF) as u8,
        ((value >> 8) & 0xFF) as u8,
        ((value >> 16) & 0xFF) as u8,
    ];
    dst.write_slice(&bytes, ctx)
}

pub(crate) fn read_u24_le(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<u32> {
    let bytes = src.read_slice(3, ctx)?;
    Ok((bytes[0] as u32) | ((bytes[1] as u32) << 8) | ((bytes[2] as u32) << 16))
}

// ── ServerIoHeader (S→C, §2.2.2.1.1) ──

/// 8-byte server-to-client I/O header prefixing every FunctionId-bearing
/// message (CreateFile/Read/Write/IoControl/IoCancel/Capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerIoHeader {
    /// 24-bit request identifier the client must echo back.
    pub request_id: u32,
    /// `UnusedBits` — ignored on receive per spec, written as 0 on send.
    pub unused_bits: u8,
    /// Message discriminator (see [`crate::constants::function_id`]).
    pub function_id: u32,
}

const SIH_CTX: &str = "ServerIoHeader";

impl ServerIoHeader {
    /// Construct with `unused_bits = 0` (spec-recommended).
    pub fn new(request_id: u32, function_id: u32) -> Self {
        Self {
            request_id,
            unused_bits: 0,
            function_id,
        }
    }

    pub(crate) fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_u24_le(dst, self.request_id, SIH_CTX)?;
        dst.write_u8(self.unused_bits, SIH_CTX)?;
        dst.write_u32_le(self.function_id, SIH_CTX)?;
        Ok(())
    }

    pub(crate) fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        if src.remaining() < SERVER_IO_HEADER_SIZE {
            return Err(DecodeError::invalid_value(SIH_CTX, "truncated header"));
        }
        let request_id = read_u24_le(src, SIH_CTX)?;
        let unused_bits = src.read_u8(SIH_CTX)?;
        let function_id = src.read_u32_le(SIH_CTX)?;
        Ok(Self {
            request_id,
            unused_bits,
            function_id,
        })
    }

    /// Verify a decoded header matches the expected `FunctionId`.
    pub(crate) fn expect_function(
        &self,
        expected: u32,
        ctx: &'static str,
    ) -> DecodeResult<()> {
        if self.function_id != expected {
            return Err(DecodeError::invalid_value(ctx, "FunctionId"));
        }
        Ok(())
    }
}

// ── ClientIoHeader (C→S, §2.2.2.1.2) ──

/// 4-byte client-to-server I/O header prefixing every response or
/// client-initiated custom event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIoHeader {
    /// 24-bit echo of the server-allocated `RequestId` that the reply is
    /// matched against. Ignored for `PacketType = CUSTOM_EVENT`.
    pub request_id: u32,
    /// `PacketType` — see [`crate::constants::packet_type`].
    pub packet_type: u8,
}

const CIH_CTX: &str = "ClientIoHeader";

impl ClientIoHeader {
    pub fn new(request_id: u32, packet_type: u8) -> Self {
        Self {
            request_id,
            packet_type,
        }
    }

    pub(crate) fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_u24_le(dst, self.request_id, CIH_CTX)?;
        dst.write_u8(self.packet_type, CIH_CTX)?;
        Ok(())
    }

    pub(crate) fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        if src.remaining() < CLIENT_IO_HEADER_SIZE {
            return Err(DecodeError::invalid_value(CIH_CTX, "truncated header"));
        }
        let request_id = read_u24_le(src, CIH_CTX)?;
        let packet_type = src.read_u8(CIH_CTX)?;
        Ok(Self {
            request_id,
            packet_type,
        })
    }

    /// Verify a decoded header matches the expected `PacketType`.
    pub(crate) fn expect_packet_type(
        &self,
        expected: u8,
        ctx: &'static str,
    ) -> DecodeResult<()> {
        if self.packet_type != expected {
            return Err(DecodeError::invalid_value(ctx, "PacketType"));
        }
        Ok(())
    }
}
