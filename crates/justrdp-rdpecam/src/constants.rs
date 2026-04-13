//! MS-RDPECAM constants: versions, message ids, and error codes.
//!
//! All values reference sections of MS-RDPECAM v5.0. Only the primitives
//! shared by every message live here; format-specific enums (media type,
//! property set, etc.) are defined next to the PDUs that use them.

// ── Protocol version (MS-RDPECAM §2.2.1) ──

/// Version 1 -- base protocol (MessageIds 0x01..=0x13).
pub const VERSION_1: u8 = 1;

/// Version 2 -- adds the Property API (MessageIds 0x14..=0x18).
pub const VERSION_2: u8 = 2;

// ── MessageId (MS-RDPECAM §2.2.1) ──

/// Client → server, device channel. Ack for Activate/Deactivate/Start/Stop/SetProperty.
pub const MSG_SUCCESS_RESPONSE: u8 = 0x01;
/// Client → server, device channel. Error result carrying an `ErrorCode`.
pub const MSG_ERROR_RESPONSE: u8 = 0x02;
/// Client → server, enumeration channel. First message on the channel.
pub const MSG_SELECT_VERSION_REQUEST: u8 = 0x03;
/// Server → client, enumeration channel. Version negotiation reply.
pub const MSG_SELECT_VERSION_RESPONSE: u8 = 0x04;
/// Client → server, enumeration channel. Attach a new camera device.
pub const MSG_DEVICE_ADDED_NOTIFICATION: u8 = 0x05;
/// Client → server, enumeration channel. Detach a camera device.
pub const MSG_DEVICE_REMOVED_NOTIFICATION: u8 = 0x06;
/// Server → client, device channel.
pub const MSG_ACTIVATE_DEVICE_REQUEST: u8 = 0x07;
/// Server → client, device channel.
pub const MSG_DEACTIVATE_DEVICE_REQUEST: u8 = 0x08;
/// Server → client, device channel.
pub const MSG_STREAM_LIST_REQUEST: u8 = 0x09;
/// Client → server, device channel.
pub const MSG_STREAM_LIST_RESPONSE: u8 = 0x0A;
/// Server → client, device channel.
pub const MSG_MEDIA_TYPE_LIST_REQUEST: u8 = 0x0B;
/// Client → server, device channel.
pub const MSG_MEDIA_TYPE_LIST_RESPONSE: u8 = 0x0C;
/// Server → client, device channel.
pub const MSG_CURRENT_MEDIA_TYPE_REQUEST: u8 = 0x0D;
/// Client → server, device channel.
pub const MSG_CURRENT_MEDIA_TYPE_RESPONSE: u8 = 0x0E;
/// Server → client, device channel.
pub const MSG_START_STREAMS_REQUEST: u8 = 0x0F;
/// Server → client, device channel.
pub const MSG_STOP_STREAMS_REQUEST: u8 = 0x10;
/// Server → client, device channel. Request for the next captured sample.
pub const MSG_SAMPLE_REQUEST: u8 = 0x11;
/// Client → server, device channel. Delivers a captured sample blob.
pub const MSG_SAMPLE_RESPONSE: u8 = 0x12;
/// Client → server, device channel. Delivered in place of a `SampleResponse` on error.
pub const MSG_SAMPLE_ERROR_RESPONSE: u8 = 0x13;
/// Server → client, device channel. v2 only.
pub const MSG_PROPERTY_LIST_REQUEST: u8 = 0x14;
/// Client → server, device channel. v2 only.
pub const MSG_PROPERTY_LIST_RESPONSE: u8 = 0x15;
/// Server → client, device channel. v2 only.
pub const MSG_PROPERTY_VALUE_REQUEST: u8 = 0x16;
/// Client → server, device channel. v2 only.
pub const MSG_PROPERTY_VALUE_RESPONSE: u8 = 0x17;
/// Server → client, device channel. v2 only.
pub const MSG_SET_PROPERTY_VALUE_REQUEST: u8 = 0x18;

/// Inclusive range of valid MessageIds in protocol version 1.
pub const MSG_RANGE_V1: core::ops::RangeInclusive<u8> =
    MSG_SUCCESS_RESPONSE..=MSG_SAMPLE_ERROR_RESPONSE;

/// Inclusive range of valid MessageIds in protocol version 2.
pub const MSG_RANGE_V2: core::ops::RangeInclusive<u8> =
    MSG_SUCCESS_RESPONSE..=MSG_SET_PROPERTY_VALUE_REQUEST;

/// Returns true for MessageIds that require a negotiated protocol version of 2.
pub fn is_v2_only(message_id: u8) -> bool {
    matches!(
        message_id,
        MSG_PROPERTY_LIST_REQUEST
            | MSG_PROPERTY_LIST_RESPONSE
            | MSG_PROPERTY_VALUE_REQUEST
            | MSG_PROPERTY_VALUE_RESPONSE
            | MSG_SET_PROPERTY_VALUE_REQUEST
    )
}

// ── ErrorCode (MS-RDPECAM §2.2.3.2) ──

/// `CAM_ERROR_CODE` -- 32-bit error values returned in an `ErrorResponse`.
///
/// The wire encoding is little-endian u32. Unknown values are preserved by
/// `ErrorCode::Other(raw)` so the decoder never rejects a message purely
/// because Microsoft expanded the enumeration later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// 0x00000001 -- unexpected condition in the client.
    UnexpectedError,
    /// 0x00000002 -- malformed or out-of-sequence message.
    InvalidMessage,
    /// 0x00000003 -- operation attempted before the device was activated.
    NotInitialized,
    /// 0x00000004 -- request references state that does not exist.
    InvalidRequest,
    /// 0x00000005 -- `StreamIndex` does not identify an existing stream.
    InvalidStreamNumber,
    /// 0x00000006 -- `MediaType` is unsupported or internally inconsistent.
    InvalidMediaType,
    /// 0x00000007 -- client-side memory allocation failure.
    OutOfMemory,
    /// 0x00000008 -- v2 only. Requested property id not present in the set.
    ItemNotFound,
    /// 0x00000009 -- v2 only. `PropertySet` is unknown.
    SetNotFound,
    /// 0x0000000A -- v2 only. Property is read-only or unsupported mode.
    OperationNotSupported,
    /// Preserved raw value for forward compatibility with future spec revisions.
    Other(u32),
}

impl ErrorCode {
    pub const UNEXPECTED_ERROR: u32 = 0x0000_0001;
    pub const INVALID_MESSAGE: u32 = 0x0000_0002;
    pub const NOT_INITIALIZED: u32 = 0x0000_0003;
    pub const INVALID_REQUEST: u32 = 0x0000_0004;
    pub const INVALID_STREAM_NUMBER: u32 = 0x0000_0005;
    pub const INVALID_MEDIA_TYPE: u32 = 0x0000_0006;
    pub const OUT_OF_MEMORY: u32 = 0x0000_0007;
    pub const ITEM_NOT_FOUND: u32 = 0x0000_0008;
    pub const SET_NOT_FOUND: u32 = 0x0000_0009;
    pub const OPERATION_NOT_SUPPORTED: u32 = 0x0000_000A;

    /// Wire representation (little-endian u32 on the wire).
    pub fn to_u32(self) -> u32 {
        match self {
            Self::UnexpectedError => Self::UNEXPECTED_ERROR,
            Self::InvalidMessage => Self::INVALID_MESSAGE,
            Self::NotInitialized => Self::NOT_INITIALIZED,
            Self::InvalidRequest => Self::INVALID_REQUEST,
            Self::InvalidStreamNumber => Self::INVALID_STREAM_NUMBER,
            Self::InvalidMediaType => Self::INVALID_MEDIA_TYPE,
            Self::OutOfMemory => Self::OUT_OF_MEMORY,
            Self::ItemNotFound => Self::ITEM_NOT_FOUND,
            Self::SetNotFound => Self::SET_NOT_FOUND,
            Self::OperationNotSupported => Self::OPERATION_NOT_SUPPORTED,
            Self::Other(raw) => raw,
        }
    }

    pub fn from_u32(raw: u32) -> Self {
        match raw {
            Self::UNEXPECTED_ERROR => Self::UnexpectedError,
            Self::INVALID_MESSAGE => Self::InvalidMessage,
            Self::NOT_INITIALIZED => Self::NotInitialized,
            Self::INVALID_REQUEST => Self::InvalidRequest,
            Self::INVALID_STREAM_NUMBER => Self::InvalidStreamNumber,
            Self::INVALID_MEDIA_TYPE => Self::InvalidMediaType,
            Self::OUT_OF_MEMORY => Self::OutOfMemory,
            Self::ITEM_NOT_FOUND => Self::ItemNotFound,
            Self::SET_NOT_FOUND => Self::SetNotFound,
            Self::OPERATION_NOT_SUPPORTED => Self::OperationNotSupported,
            other => Self::Other(other),
        }
    }

    /// True for error codes that MUST only be sent on a v2-negotiated channel.
    pub fn is_v2_only(self) -> bool {
        matches!(
            self,
            Self::ItemNotFound | Self::SetNotFound | Self::OperationNotSupported
        )
    }
}
