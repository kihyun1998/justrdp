//! MS-RDPEPNP §2.2.2.2 / §2.2.2.3 — FileRedirectorChannel I/O PDUs.
//!
//! This module implements the ten wire messages used on an instance of
//! the `"FileRedirectorChannel"` dynamic virtual channel:
//!
//! | Direction | Type                        | Section         | Fixed size? |
//! | --------- | --------------------------- | --------------- | ----------- |
//! | S→C       | [`ServerCapabilitiesRequest`] | §2.2.2.2.1      | 10 bytes    |
//! | C→S       | [`ClientCapabilitiesReply`] | §2.2.2.2.2      | 6 bytes     |
//! | S→C       | [`CreateFileRequest`]       | §2.2.2.3.1      | 28 bytes    |
//! | C→S       | [`CreateFileReply`]         | §2.2.2.3.2      | 8 bytes     |
//! | S→C       | [`ReadRequest`]             | §2.2.2.3.3      | 20 bytes    |
//! | C→S       | [`ReadReply`]               | §2.2.2.3.4      | 13 + data   |
//! | S→C       | [`WriteRequest`]            | §2.2.2.3.5      | 21 + data   |
//! | C→S       | [`WriteReply`]              | §2.2.2.3.6      | 12 bytes    |
//! | S→C       | [`IoControlRequest`]        | §2.2.2.3.7      | 21 + in+out |
//! | C→S       | [`IoControlReply`]          | §2.2.2.3.8      | 13 + data   |
//! | S→C       | [`SpecificIoCancelRequest`] | §2.2.2.3.9      | 12 bytes    |
//! | C→S       | [`ClientDeviceCustomEvent`] | §2.2.2.3.10     | 25 + data   |
//!
//! All multi-byte fields are little-endian. Reply/request bodies that
//! carry a variable `Data`/`DataIn`/`DataOut` buffer are followed by a
//! mandatory 1-byte `UnusedByte` pad; that byte is encoded as 0 and
//! silently consumed on decode regardless of its value.

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{
    function_id, packet_type, CLIENT_IO_HEADER_SIZE, MAX_CUSTOM_EVENT_BYTES, MAX_IOCONTROL_BYTES,
    MAX_READ_BYTES, MAX_WRITE_BYTES, SERVER_IO_HEADER_SIZE,
};
use crate::pdu::io_header::{ClientIoHeader, ServerIoHeader};

// ── Fixed wire sizes ──

pub const SERVER_CAPS_REQUEST_SIZE: usize = SERVER_IO_HEADER_SIZE + 2;
pub const CLIENT_CAPS_REPLY_SIZE: usize = CLIENT_IO_HEADER_SIZE + 2;
pub const CREATE_FILE_REQUEST_SIZE: usize = SERVER_IO_HEADER_SIZE + 20;
pub const CREATE_FILE_REPLY_SIZE: usize = CLIENT_IO_HEADER_SIZE + 4;
pub const READ_REQUEST_SIZE: usize = SERVER_IO_HEADER_SIZE + 12;
/// Minimum `ReadReply` size — `cbBytesRead = 0`, still includes the
/// trailing `UnusedByte` pad (§2.2.2.3.4).
pub const READ_REPLY_MIN_SIZE: usize = CLIENT_IO_HEADER_SIZE + 4 + 4 + 1;
/// Minimum `WriteRequest` size — `cbWrite = 0`, still includes the
/// trailing `UnusedByte` pad (§2.2.2.3.5).
pub const WRITE_REQUEST_MIN_SIZE: usize = SERVER_IO_HEADER_SIZE + 12 + 1;
pub const WRITE_REPLY_SIZE: usize = CLIENT_IO_HEADER_SIZE + 4 + 4;
/// Minimum `IoControlRequest` size — `cbIn = cbOut = 0`, still includes
/// the trailing `UnusedByte` pad (§2.2.2.3.7).
pub const IOCONTROL_REQUEST_MIN_SIZE: usize = SERVER_IO_HEADER_SIZE + 12 + 1;
/// Minimum `IoControlReply` size — `cbBytesReadReturned = 0`, still
/// includes the trailing `UnusedByte` pad (§2.2.2.3.8).
pub const IOCONTROL_REPLY_MIN_SIZE: usize = CLIENT_IO_HEADER_SIZE + 4 + 4 + 1;
pub const SPECIFIC_IOCANCEL_REQUEST_SIZE: usize = SERVER_IO_HEADER_SIZE + 4;
/// Minimum `ClientDeviceCustomEvent` size — `cbData = 0`, still
/// includes the trailing `UnusedByte` pad (§2.2.2.3.10).
pub const CUSTOM_EVENT_MIN_SIZE: usize = CLIENT_IO_HEADER_SIZE + 16 + 4 + 1;

// ── ServerCapabilitiesRequest (S→C, §2.2.2.2.1) ──

/// Server→client capability negotiation carrying the server's preferred
/// protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerCapabilitiesRequest {
    pub request_id: u32,
    /// `0x0004` = custom-event unsupported; `0x0006` = custom-event
    /// supported. The negotiated version is `min(server, client)`.
    pub version: u16,
}

const SCR_CTX: &str = "ServerCapabilitiesRequest";

impl Encode for ServerCapabilitiesRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ServerIoHeader::new(self.request_id, function_id::CAPABILITIES_REQUEST).encode(dst)?;
        dst.write_u16_le(self.version, SCR_CTX)?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        SCR_CTX
    }
    fn size(&self) -> usize {
        SERVER_CAPS_REQUEST_SIZE
    }
}

impl<'de> Decode<'de> for ServerCapabilitiesRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = ServerIoHeader::decode(src)?;
        hdr.expect_function(function_id::CAPABILITIES_REQUEST, SCR_CTX)?;
        let version = src.read_u16_le(SCR_CTX)?;
        Ok(Self {
            request_id: hdr.request_id,
            version,
        })
    }
}

// ── ClientCapabilitiesReply (C→S, §2.2.2.2.2) ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientCapabilitiesReply {
    pub request_id: u32,
    pub version: u16,
}

const CCR_CTX: &str = "ClientCapabilitiesReply";

impl Encode for ClientCapabilitiesReply {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ClientIoHeader::new(self.request_id, packet_type::RESPONSE).encode(dst)?;
        dst.write_u16_le(self.version, CCR_CTX)?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        CCR_CTX
    }
    fn size(&self) -> usize {
        CLIENT_CAPS_REPLY_SIZE
    }
}

impl<'de> Decode<'de> for ClientCapabilitiesReply {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = ClientIoHeader::decode(src)?;
        hdr.expect_packet_type(packet_type::RESPONSE, CCR_CTX)?;
        let version = src.read_u16_le(CCR_CTX)?;
        Ok(Self {
            request_id: hdr.request_id,
            version,
        })
    }
}

// ── CreateFileRequest (S→C, §2.2.2.3.1) ──

/// Server→client open request. Exactly one of these is sent per
/// FileRedirectorChannel instance, immediately after the capability
/// exchange completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateFileRequest {
    pub request_id: u32,
    /// ClientDeviceID previously announced via PNPDR.
    pub device_id: u32,
    pub desired_access: u32,
    pub share_mode: u32,
    pub creation_disposition: u32,
    pub flags_and_attributes: u32,
}

const CFR_CTX: &str = "CreateFileRequest";

impl Encode for CreateFileRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ServerIoHeader::new(self.request_id, function_id::CREATE_FILE_REQUEST).encode(dst)?;
        dst.write_u32_le(self.device_id, CFR_CTX)?;
        dst.write_u32_le(self.desired_access, CFR_CTX)?;
        dst.write_u32_le(self.share_mode, CFR_CTX)?;
        dst.write_u32_le(self.creation_disposition, CFR_CTX)?;
        dst.write_u32_le(self.flags_and_attributes, CFR_CTX)?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        CFR_CTX
    }
    fn size(&self) -> usize {
        CREATE_FILE_REQUEST_SIZE
    }
}

impl<'de> Decode<'de> for CreateFileRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = ServerIoHeader::decode(src)?;
        hdr.expect_function(function_id::CREATE_FILE_REQUEST, CFR_CTX)?;
        Ok(Self {
            request_id: hdr.request_id,
            device_id: src.read_u32_le(CFR_CTX)?,
            desired_access: src.read_u32_le(CFR_CTX)?,
            share_mode: src.read_u32_le(CFR_CTX)?,
            creation_disposition: src.read_u32_le(CFR_CTX)?,
            flags_and_attributes: src.read_u32_le(CFR_CTX)?,
        })
    }
}

// ── CreateFileReply (C→S, §2.2.2.3.2) ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateFileReply {
    pub request_id: u32,
    /// HRESULT — 0 = success, non-zero = device-specific failure code.
    pub result: i32,
}

const CFRR_CTX: &str = "CreateFileReply";

impl Encode for CreateFileReply {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ClientIoHeader::new(self.request_id, packet_type::RESPONSE).encode(dst)?;
        dst.write_i32_le(self.result, CFRR_CTX)?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        CFRR_CTX
    }
    fn size(&self) -> usize {
        CREATE_FILE_REPLY_SIZE
    }
}

impl<'de> Decode<'de> for CreateFileReply {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = ClientIoHeader::decode(src)?;
        hdr.expect_packet_type(packet_type::RESPONSE, CFRR_CTX)?;
        Ok(Self {
            request_id: hdr.request_id,
            result: src.read_i32_le(CFRR_CTX)?,
        })
    }
}

// ── ReadRequest (S→C, §2.2.2.3.3) ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadRequest {
    pub request_id: u32,
    pub cb_bytes_to_read: u32,
    pub offset_high: u32,
    pub offset_low: u32,
}

const RR_CTX: &str = "ReadRequest";

impl ReadRequest {
    /// Compose the 64-bit file offset from the `OffsetHigh`/`OffsetLow`
    /// pair the spec splits it into.
    pub fn offset(&self) -> u64 {
        ((self.offset_high as u64) << 32) | (self.offset_low as u64)
    }
}

impl Encode for ReadRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ServerIoHeader::new(self.request_id, function_id::READ_REQUEST).encode(dst)?;
        dst.write_u32_le(self.cb_bytes_to_read, RR_CTX)?;
        dst.write_u32_le(self.offset_high, RR_CTX)?;
        dst.write_u32_le(self.offset_low, RR_CTX)?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        RR_CTX
    }
    fn size(&self) -> usize {
        READ_REQUEST_SIZE
    }
}

impl<'de> Decode<'de> for ReadRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = ServerIoHeader::decode(src)?;
        hdr.expect_function(function_id::READ_REQUEST, RR_CTX)?;
        let cb_bytes_to_read = src.read_u32_le(RR_CTX)?;
        if cb_bytes_to_read as usize > MAX_READ_BYTES {
            return Err(DecodeError::invalid_value(RR_CTX, "cbBytesToRead cap"));
        }
        Ok(Self {
            request_id: hdr.request_id,
            cb_bytes_to_read,
            offset_high: src.read_u32_le(RR_CTX)?,
            offset_low: src.read_u32_le(RR_CTX)?,
        })
    }
}

// ── ReadReply (C→S, §2.2.2.3.4) ──

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadReply {
    pub request_id: u32,
    pub result: i32,
    /// Exactly `data.len()` — kept as a single field so over-/under-sized
    /// data slices cannot drift away from the wire length.
    pub data: Vec<u8>,
}

const RP_CTX: &str = "ReadReply";

impl Encode for ReadReply {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.data.len() > MAX_READ_BYTES {
            return Err(EncodeError::invalid_value(RP_CTX, "Data > MAX_READ_BYTES"));
        }
        if self.data.len() > u32::MAX as usize {
            return Err(EncodeError::invalid_value(RP_CTX, "cbBytesRead overflow"));
        }
        ClientIoHeader::new(self.request_id, packet_type::RESPONSE).encode(dst)?;
        dst.write_i32_le(self.result, RP_CTX)?;
        dst.write_u32_le(self.data.len() as u32, RP_CTX)?;
        dst.write_slice(&self.data, RP_CTX)?;
        dst.write_u8(0, RP_CTX)?; // UnusedByte (§2.2.2.3.4)
        Ok(())
    }
    fn name(&self) -> &'static str {
        RP_CTX
    }
    fn size(&self) -> usize {
        READ_REPLY_MIN_SIZE + self.data.len()
    }
}

impl<'de> Decode<'de> for ReadReply {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = ClientIoHeader::decode(src)?;
        hdr.expect_packet_type(packet_type::RESPONSE, RP_CTX)?;
        let result = src.read_i32_le(RP_CTX)?;
        let cb = src.read_u32_le(RP_CTX)? as usize;
        if cb > MAX_READ_BYTES {
            return Err(DecodeError::invalid_value(RP_CTX, "cbBytesRead cap"));
        }
        let data = src.read_slice(cb, RP_CTX)?.to_vec();
        let _unused = src.read_u8(RP_CTX)?;
        Ok(Self {
            request_id: hdr.request_id,
            result,
            data,
        })
    }
}

// ── WriteRequest (S→C, §2.2.2.3.5) ──

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRequest {
    pub request_id: u32,
    pub offset_high: u32,
    pub offset_low: u32,
    pub data: Vec<u8>,
}

const WR_CTX: &str = "WriteRequest";

impl WriteRequest {
    pub fn offset(&self) -> u64 {
        ((self.offset_high as u64) << 32) | (self.offset_low as u64)
    }
}

impl Encode for WriteRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.data.len() > MAX_WRITE_BYTES {
            return Err(EncodeError::invalid_value(WR_CTX, "Data > MAX_WRITE_BYTES"));
        }
        if self.data.len() > u32::MAX as usize {
            return Err(EncodeError::invalid_value(WR_CTX, "cbWrite overflow"));
        }
        ServerIoHeader::new(self.request_id, function_id::WRITE_REQUEST).encode(dst)?;
        dst.write_u32_le(self.data.len() as u32, WR_CTX)?;
        dst.write_u32_le(self.offset_high, WR_CTX)?;
        dst.write_u32_le(self.offset_low, WR_CTX)?;
        dst.write_slice(&self.data, WR_CTX)?;
        dst.write_u8(0, WR_CTX)?; // UnusedByte (§2.2.2.3.5)
        Ok(())
    }
    fn name(&self) -> &'static str {
        WR_CTX
    }
    fn size(&self) -> usize {
        WRITE_REQUEST_MIN_SIZE + self.data.len()
    }
}

impl<'de> Decode<'de> for WriteRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = ServerIoHeader::decode(src)?;
        hdr.expect_function(function_id::WRITE_REQUEST, WR_CTX)?;
        let cb = src.read_u32_le(WR_CTX)? as usize;
        if cb > MAX_WRITE_BYTES {
            return Err(DecodeError::invalid_value(WR_CTX, "cbWrite cap"));
        }
        let offset_high = src.read_u32_le(WR_CTX)?;
        let offset_low = src.read_u32_le(WR_CTX)?;
        let data = src.read_slice(cb, WR_CTX)?.to_vec();
        let _unused = src.read_u8(WR_CTX)?;
        Ok(Self {
            request_id: hdr.request_id,
            offset_high,
            offset_low,
            data,
        })
    }
}

// ── WriteReply (C→S, §2.2.2.3.6) ──

/// Unlike the other reply types, `WriteReply` has **no** trailing
/// `UnusedByte` — the spec gives a fixed 12-byte shape (§2.2.2.3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteReply {
    pub request_id: u32,
    pub result: i32,
    pub cb_bytes_written: u32,
}

const WP_CTX: &str = "WriteReply";

impl Encode for WriteReply {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ClientIoHeader::new(self.request_id, packet_type::RESPONSE).encode(dst)?;
        dst.write_i32_le(self.result, WP_CTX)?;
        dst.write_u32_le(self.cb_bytes_written, WP_CTX)?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        WP_CTX
    }
    fn size(&self) -> usize {
        WRITE_REPLY_SIZE
    }
}

impl<'de> Decode<'de> for WriteReply {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = ClientIoHeader::decode(src)?;
        hdr.expect_packet_type(packet_type::RESPONSE, WP_CTX)?;
        Ok(Self {
            request_id: hdr.request_id,
            result: src.read_i32_le(WP_CTX)?,
            cb_bytes_written: src.read_u32_le(WP_CTX)?,
        })
    }
}

// ── IoControlRequest (S→C, §2.2.2.3.7) ──

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoControlRequest {
    pub request_id: u32,
    /// Device-specific IOCTL code. The spec does not define any.
    pub io_code: u32,
    pub data_in: Vec<u8>,
    /// `cbOut` — advertised output buffer size the client should
    /// allocate. The spec places the `DataOut` bytes inside the request
    /// body as well, but real wire traces always have `DataOut.len() = 0`
    /// and the spec marks that field as SHOULD, so we model it as a
    /// plain byte vector whose length need not equal `cb_out`.
    pub cb_out: u32,
    pub data_out: Vec<u8>,
}

const IOCR_CTX: &str = "IoControlRequest";

impl Encode for IoControlRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.data_in.len() > MAX_IOCONTROL_BYTES {
            return Err(EncodeError::invalid_value(IOCR_CTX, "cbIn cap"));
        }
        if self.data_out.len() > MAX_IOCONTROL_BYTES {
            return Err(EncodeError::invalid_value(IOCR_CTX, "DataOut cap"));
        }
        if (self.cb_out as usize) > MAX_IOCONTROL_BYTES {
            return Err(EncodeError::invalid_value(IOCR_CTX, "cbOut cap"));
        }
        if self.data_in.len() > u32::MAX as usize {
            return Err(EncodeError::invalid_value(IOCR_CTX, "cbIn overflow"));
        }
        ServerIoHeader::new(self.request_id, function_id::IOCONTROL_REQUEST).encode(dst)?;
        dst.write_u32_le(self.io_code, IOCR_CTX)?;
        dst.write_u32_le(self.data_in.len() as u32, IOCR_CTX)?;
        dst.write_u32_le(self.cb_out, IOCR_CTX)?;
        dst.write_slice(&self.data_in, IOCR_CTX)?;
        dst.write_slice(&self.data_out, IOCR_CTX)?;
        dst.write_u8(0, IOCR_CTX)?; // UnusedByte (§2.2.2.3.7)
        Ok(())
    }
    fn name(&self) -> &'static str {
        IOCR_CTX
    }
    fn size(&self) -> usize {
        IOCONTROL_REQUEST_MIN_SIZE + self.data_in.len() + self.data_out.len()
    }
}

impl<'de> Decode<'de> for IoControlRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = ServerIoHeader::decode(src)?;
        hdr.expect_function(function_id::IOCONTROL_REQUEST, IOCR_CTX)?;
        let io_code = src.read_u32_le(IOCR_CTX)?;
        let cb_in = src.read_u32_le(IOCR_CTX)? as usize;
        let cb_out = src.read_u32_le(IOCR_CTX)?;
        if cb_in > MAX_IOCONTROL_BYTES {
            return Err(DecodeError::invalid_value(IOCR_CTX, "cbIn cap"));
        }
        if (cb_out as usize) > MAX_IOCONTROL_BYTES {
            return Err(DecodeError::invalid_value(IOCR_CTX, "cbOut cap"));
        }
        let data_in = src.read_slice(cb_in, IOCR_CTX)?.to_vec();
        // Spec §2.2.2.3.7 says the DataOut field SHOULD equal cbOut,
        // but the wire trace in §4 carries `cbOut=8, DataOut=0` —
        // the spec's own example violates its SHOULD. We therefore
        // accept any DataOut length in `[0, cb_out]`, preserving the
        // actual byte count in `data_out` while keeping `cb_out`
        // intact for the callback to use when sizing its reply.
        let tail = src
            .remaining()
            .checked_sub(1)
            .ok_or_else(|| DecodeError::invalid_value(IOCR_CTX, "missing UnusedByte"))?;
        if tail > cb_out as usize {
            return Err(DecodeError::invalid_value(IOCR_CTX, "DataOut > cbOut"));
        }
        let data_out = src.read_slice(tail, IOCR_CTX)?.to_vec();
        let _unused = src.read_u8(IOCR_CTX)?;
        Ok(Self {
            request_id: hdr.request_id,
            io_code,
            data_in,
            cb_out,
            data_out,
        })
    }
}

// ── IoControlReply (C→S, §2.2.2.3.8) ──

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoControlReply {
    pub request_id: u32,
    pub result: i32,
    /// Returned bytes. Must not exceed the `cb_out` of the matching
    /// request — the FSM enforces this, not the decoder.
    pub data: Vec<u8>,
}

const IOCP_CTX: &str = "IoControlReply";

impl Encode for IoControlReply {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.data.len() > MAX_IOCONTROL_BYTES {
            return Err(EncodeError::invalid_value(IOCP_CTX, "Data cap"));
        }
        if self.data.len() > u32::MAX as usize {
            return Err(EncodeError::invalid_value(IOCP_CTX, "cbBytesReadReturned overflow"));
        }
        ClientIoHeader::new(self.request_id, packet_type::RESPONSE).encode(dst)?;
        dst.write_i32_le(self.result, IOCP_CTX)?;
        dst.write_u32_le(self.data.len() as u32, IOCP_CTX)?;
        dst.write_slice(&self.data, IOCP_CTX)?;
        dst.write_u8(0, IOCP_CTX)?; // UnusedByte (§2.2.2.3.8)
        Ok(())
    }
    fn name(&self) -> &'static str {
        IOCP_CTX
    }
    fn size(&self) -> usize {
        IOCONTROL_REPLY_MIN_SIZE + self.data.len()
    }
}

impl<'de> Decode<'de> for IoControlReply {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = ClientIoHeader::decode(src)?;
        hdr.expect_packet_type(packet_type::RESPONSE, IOCP_CTX)?;
        let result = src.read_i32_le(IOCP_CTX)?;
        let cb = src.read_u32_le(IOCP_CTX)? as usize;
        if cb > MAX_IOCONTROL_BYTES {
            return Err(DecodeError::invalid_value(IOCP_CTX, "cbBytesReadReturned cap"));
        }
        let data = src.read_slice(cb, IOCP_CTX)?.to_vec();
        let _unused = src.read_u8(IOCP_CTX)?;
        Ok(Self {
            request_id: hdr.request_id,
            result,
            data,
        })
    }
}

// ── SpecificIoCancelRequest (S→C, §2.2.2.3.9) ──

/// Has no matching client reply — the spec never defines one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecificIoCancelRequest {
    /// RequestId of the cancel message itself.
    pub request_id: u32,
    /// `UnusedBits` — 8 bits immediately before `idToCancel`. Written
    /// as 0, ignored on receive.
    pub unused_bits: u8,
    /// 24-bit RequestId of a previously issued request the server
    /// wants to cancel.
    pub id_to_cancel: u32,
}

const SIC_CTX: &str = "SpecificIoCancelRequest";

impl Encode for SpecificIoCancelRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ServerIoHeader::new(self.request_id, function_id::SPECIFIC_IOCANCEL_REQUEST)
            .encode(dst)?;
        dst.write_u8(self.unused_bits, SIC_CTX)?;
        crate::pdu::io_header::write_u24_le(dst, self.id_to_cancel, SIC_CTX)?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        SIC_CTX
    }
    fn size(&self) -> usize {
        SPECIFIC_IOCANCEL_REQUEST_SIZE
    }
}

impl<'de> Decode<'de> for SpecificIoCancelRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = ServerIoHeader::decode(src)?;
        hdr.expect_function(function_id::SPECIFIC_IOCANCEL_REQUEST, SIC_CTX)?;
        let unused_bits = src.read_u8(SIC_CTX)?;
        let id_to_cancel = crate::pdu::io_header::read_u24_le(src, SIC_CTX)?;
        Ok(Self {
            request_id: hdr.request_id,
            unused_bits,
            id_to_cancel,
        })
    }
}

// ── ClientDeviceCustomEvent (C→S, §2.2.2.3.10) ──

/// Asynchronous client-initiated notification. Only valid once both
/// peers have negotiated version 0x0006 (§2.2.2.3.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDeviceCustomEvent {
    /// SHOULD be `0x000000` per §2.2.2.3.10 but the spec allows any
    /// value — we preserve it verbatim.
    pub request_id: u32,
    /// Event type identifier. Stored as a raw 16-byte little-endian
    /// GUID blob to avoid an opinionated GUID type.
    pub custom_event_guid: [u8; 16],
    /// Payload bytes. `cbData` on the wire equals `data.len()`.
    pub data: Vec<u8>,
}

const CDCE_CTX: &str = "ClientDeviceCustomEvent";

impl Encode for ClientDeviceCustomEvent {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.data.len() > MAX_CUSTOM_EVENT_BYTES {
            return Err(EncodeError::invalid_value(CDCE_CTX, "cbData cap"));
        }
        if self.data.len() > u32::MAX as usize {
            return Err(EncodeError::invalid_value(CDCE_CTX, "cbData overflow"));
        }
        ClientIoHeader::new(self.request_id, packet_type::CUSTOM_EVENT).encode(dst)?;
        dst.write_slice(&self.custom_event_guid, CDCE_CTX)?;
        dst.write_u32_le(self.data.len() as u32, CDCE_CTX)?;
        dst.write_slice(&self.data, CDCE_CTX)?;
        dst.write_u8(0, CDCE_CTX)?; // UnusedByte (§2.2.2.3.10)
        Ok(())
    }
    fn name(&self) -> &'static str {
        CDCE_CTX
    }
    fn size(&self) -> usize {
        CUSTOM_EVENT_MIN_SIZE + self.data.len()
    }
}

impl<'de> Decode<'de> for ClientDeviceCustomEvent {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = ClientIoHeader::decode(src)?;
        hdr.expect_packet_type(packet_type::CUSTOM_EVENT, CDCE_CTX)?;
        let mut guid = [0u8; 16];
        guid.copy_from_slice(src.read_slice(16, CDCE_CTX)?);
        let cb = src.read_u32_le(CDCE_CTX)? as usize;
        if cb > MAX_CUSTOM_EVENT_BYTES {
            return Err(DecodeError::invalid_value(CDCE_CTX, "cbData cap"));
        }
        let data = src.read_slice(cb, CDCE_CTX)?.to_vec();
        let _unused = src.read_u8(CDCE_CTX)?;
        Ok(Self {
            request_id: hdr.request_id,
            custom_event_guid: guid,
            data,
        })
    }
}
