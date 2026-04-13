#![forbid(unsafe_code)]

//! MS-RDPEUSB wire-format PDUs.
//!
//! Every struct cites the relevant section of `[MS-RDPEUSB]` (v20240423,
//! Rev 19.0). All multi-byte fields are little-endian unless noted.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

// =============================================================================
// Channel name and well-known constants
// =============================================================================

/// URBDRC control-channel name. MS-RDPEUSB 2.1
pub const CHANNEL_NAME: &str = "URBDRC";

// ── Mask values (MS-RDPEUSB 2.2.1) ──
pub const STREAM_ID_NONE: u32 = 0x0;
pub const STREAM_ID_PROXY: u32 = 0x1;
pub const STREAM_ID_STUB: u32 = 0x2;

// ── Well-known InterfaceId values (MS-RDPEUSB 2.2.1, 2.2.3-2.2.5) ──
pub const IID_CAPABILITY_NEGOTIATOR: u32 = 0x0000_0000;
pub const IID_DEVICE_SINK: u32 = 0x0000_0001;
pub const IID_CHANNEL_NOTIFICATION_S2C: u32 = 0x0000_0002;
pub const IID_CHANNEL_NOTIFICATION_C2S: u32 = 0x0000_0003;

// ── Common function IDs (MS-RDPEUSB 2.2.1) ──
pub const RIMCALL_RELEASE: u32 = 0x0000_0001;
pub const RIMCALL_QUERY_INTERFACE: u32 = 0x0000_0002;

// ── Capability Negotiator (IID=0) ──
pub const FN_RIM_EXCHANGE_CAPABILITY_REQUEST: u32 = 0x0000_0100;

// ── Device Sink (IID=1) ──
pub const FN_ADD_VIRTUAL_CHANNEL: u32 = 0x0000_0100;
pub const FN_ADD_DEVICE: u32 = 0x0000_0101;

// ── Channel Notification (IID=2 or 3) ──
pub const FN_CHANNEL_CREATED: u32 = 0x0000_0100;

// ── Server USB Device Interface (IID=UsbDevice) ──
pub const FN_CANCEL_REQUEST: u32 = 0x0000_0100;
pub const FN_REGISTER_REQUEST_CALLBACK: u32 = 0x0000_0101;
pub const FN_IO_CONTROL: u32 = 0x0000_0102;
pub const FN_INTERNAL_IO_CONTROL: u32 = 0x0000_0103;
pub const FN_QUERY_DEVICE_TEXT: u32 = 0x0000_0104;
pub const FN_TRANSFER_IN_REQUEST: u32 = 0x0000_0105;
pub const FN_TRANSFER_OUT_REQUEST: u32 = 0x0000_0106;
pub const FN_RETRACT_DEVICE: u32 = 0x0000_0107;

// ── Request Completion Interface (IID=RequestCompletion) ──
pub const FN_IOCONTROL_COMPLETION: u32 = 0x0000_0100;
pub const FN_URB_COMPLETION: u32 = 0x0000_0101;
pub const FN_URB_COMPLETION_NO_DATA: u32 = 0x0000_0102;

/// Capability exchange version. MS-RDPEUSB 2.2.3.1
pub const RIM_CAPABILITY_VERSION_01: u32 = 0x0000_0001;

/// `UsbRetractReason_BlockedByPolicy`. MS-RDPEUSB 2.2.8
pub const USB_RETRACT_REASON_BLOCKED_BY_POLICY: u32 = 0x0000_0001;

// ── HRESULT values (MS-RDPEUSB 2.2.7.1, Windows SDK) ──
pub const HRESULT_S_OK: u32 = 0x0000_0000;
pub const HRESULT_E_FAIL: u32 = 0x8000_4005;
pub const HRESULT_FROM_WIN32_ERROR_INSUFFICIENT_BUFFER: u32 = 0x8007_007A;
pub const HRESULT_STATUS_TIMEOUT: u32 = 0xC019_0036;

/// `S_OK` test helper.
#[inline]
pub fn hresult_is_success(h: u32) -> bool {
    (h & 0x8000_0000) == 0
}

// =============================================================================
// DoS / safety caps (checklist section 12)
// =============================================================================

pub const MAX_TRANSFER_OUTPUT_BUFFER_SIZE: u32 = 16 * 1024 * 1024;
pub const MAX_IOCTL_BUFFER_SIZE: u32 = 64 * 1024;
pub const MAX_CB_TS_URB: u32 = 64 * 1024;
pub const MAX_ISOCH_PACKETS: u32 = 1024;
pub const MAX_DEVICE_PIPES: u32 = 64;
pub const MAX_SELECT_CONFIG_INTERFACES: u32 = 32;
pub const MAX_DEVICE_INSTANCE_ID_CHARS: u32 = 1024;
pub const MAX_HARDWARE_IDS_CHARS: u32 = 4096;
pub const MAX_COMPATIBILITY_IDS_CHARS: u32 = 4096;
pub const MAX_CONTAINER_ID_CHARS: u32 = 40;
pub const MAX_DEVICE_DESCRIPTION_CHARS: u32 = 1024;
pub const MAX_PDU_SIZE: u32 = 32 * 1024 * 1024;
pub const MAX_IN_FLIGHT_REQUESTS_PER_DEVICE: usize = 1024;

// =============================================================================
// SHARED_MSG_HEADER (MS-RDPEUSB 2.2.1)
// =============================================================================

/// Mask field (high 2 bits of the first 32-bit word).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Mask {
    /// `STREAM_ID_NONE` — capability exchange only. MS-RDPEUSB 2.2.1
    StreamIdNone = 0,
    /// `STREAM_ID_PROXY` — non-response (request / notification).
    StreamIdProxy = 1,
    /// `STREAM_ID_STUB` — response message.
    StreamIdStub = 2,
}

impl Mask {
    /// Decode from the raw 2-bit value.
    pub fn from_bits(bits: u32) -> Option<Self> {
        match bits & 0x3 {
            0 => Some(Self::StreamIdNone),
            1 => Some(Self::StreamIdProxy),
            2 => Some(Self::StreamIdStub),
            _ => None,
        }
    }

    /// Returns the 2-bit numeric value.
    pub fn as_bits(self) -> u32 {
        self as u32
    }

    /// `true` iff a response header (no `FunctionId`).
    pub fn is_response(self) -> bool {
        matches!(self, Self::StreamIdStub)
    }
}

/// `SHARED_MSG_HEADER`. MS-RDPEUSB 2.2.1
///
/// Request/notification headers (`STREAM_ID_NONE` / `STREAM_ID_PROXY`) are
/// 12 bytes and carry a `FunctionId`. Response headers (`STREAM_ID_STUB`)
/// are 8 bytes and omit the `FunctionId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedMsgHeader {
    /// 30-bit interface identifier. MUST be `<= 0x3FFF_FFFF`.
    pub interface_id: u32,
    pub mask: Mask,
    pub message_id: u32,
    /// `None` for `STREAM_ID_STUB` responses.
    pub function_id: Option<u32>,
}

impl SharedMsgHeader {
    /// Bytes occupied by a request / notification header.
    pub const REQUEST_SIZE: usize = 12;
    /// Bytes occupied by a response header.
    pub const RESPONSE_SIZE: usize = 8;

    /// 30-bit mask for `InterfaceId`. MS-RDPEUSB 2.2.1
    pub const INTERFACE_ID_MASK: u32 = 0x3FFF_FFFF;

    /// Build a request-style header (with `FunctionId`).
    pub fn request(interface_id: u32, mask: Mask, message_id: u32, function_id: u32) -> Self {
        Self {
            interface_id,
            mask,
            message_id,
            function_id: Some(function_id),
        }
    }

    /// Build a response-style header (`STREAM_ID_STUB`, no `FunctionId`).
    pub fn response(interface_id: u32, message_id: u32) -> Self {
        Self {
            interface_id,
            mask: Mask::StreamIdStub,
            message_id,
            function_id: None,
        }
    }

    /// Wire size of this header.
    pub fn size(&self) -> usize {
        if self.function_id.is_some() {
            Self::REQUEST_SIZE
        } else {
            Self::RESPONSE_SIZE
        }
    }

    /// Encode the header into `dst`.
    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.interface_id > Self::INTERFACE_ID_MASK {
            return Err(EncodeError::invalid_value(
                "SharedMsgHeader",
                "InterfaceId > 0x3FFF_FFFF",
            ));
        }
        // MS-RDPEUSB 2.2.1: bits [0..30] = InterfaceId, bits [30..32] = Mask.
        let word0 = (self.interface_id & Self::INTERFACE_ID_MASK)
            | ((self.mask.as_bits() & 0x3) << 30);
        dst.write_u32_le(word0, "SharedMsgHeader::Word0")?;
        dst.write_u32_le(self.message_id, "SharedMsgHeader::MessageId")?;
        match (self.mask, self.function_id) {
            (Mask::StreamIdStub, Some(_)) => {
                return Err(EncodeError::invalid_value(
                    "SharedMsgHeader",
                    "STREAM_ID_STUB must not carry FunctionId",
                ));
            }
            (Mask::StreamIdStub, None) => {}
            (_, Some(fid)) => {
                dst.write_u32_le(fid, "SharedMsgHeader::FunctionId")?;
            }
            (_, None) => {
                return Err(EncodeError::invalid_value(
                    "SharedMsgHeader",
                    "non-STUB header requires FunctionId",
                ));
            }
        }
        Ok(())
    }

    /// Decode a request/notification header (12 bytes, `FunctionId` present).
    pub fn decode_request(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let word0 = src.read_u32_le("SharedMsgHeader::Word0")?;
        let interface_id = word0 & Self::INTERFACE_ID_MASK;
        let mask_bits = (word0 >> 30) & 0x3;
        let mask = Mask::from_bits(mask_bits).ok_or_else(|| {
            DecodeError::invalid_value("SharedMsgHeader", "Mask (unreachable)")
        })?;
        if mask == Mask::StreamIdStub {
            return Err(DecodeError::unexpected_value(
                "SharedMsgHeader",
                "Mask",
                "STREAM_ID_STUB in request slot",
            ));
        }
        let message_id = src.read_u32_le("SharedMsgHeader::MessageId")?;
        let function_id = src.read_u32_le("SharedMsgHeader::FunctionId")?;
        Ok(Self {
            interface_id,
            mask,
            message_id,
            function_id: Some(function_id),
        })
    }

    /// Decode a response header (8 bytes, no `FunctionId`).
    pub fn decode_response(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let word0 = src.read_u32_le("SharedMsgHeader::Word0")?;
        let interface_id = word0 & Self::INTERFACE_ID_MASK;
        let mask_bits = (word0 >> 30) & 0x3;
        let mask = Mask::from_bits(mask_bits).ok_or_else(|| {
            DecodeError::invalid_value("SharedMsgHeader", "Mask")
        })?;
        // NOTE: RIM_EXCHANGE_CAPABILITY_RESPONSE uses STREAM_ID_NONE as a
        // special case. QUERY_DEVICE_TEXT_RSP uses STREAM_ID_STUB. We accept
        // either here; callers verify the mask against their own contract.
        let message_id = src.read_u32_le("SharedMsgHeader::MessageId")?;
        Ok(Self {
            interface_id,
            mask,
            message_id,
            function_id: None,
        })
    }
}

/// Convenience: size of a request header. MS-RDPEUSB 2.2.1
#[inline]
pub fn request_header_size() -> usize {
    SharedMsgHeader::REQUEST_SIZE
}

/// Convenience: size of a response header. MS-RDPEUSB 2.2.1
#[inline]
pub fn response_header_size() -> usize {
    SharedMsgHeader::RESPONSE_SIZE
}

// =============================================================================
// UTF-16 helpers
// =============================================================================

/// NUL-terminated UTF-16LE string. `chars` DOES NOT include the NUL; the
/// encode/decode helpers add / strip it when the wire count convention
/// (`cch` includes the terminator) is used.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Utf16String {
    /// Code units, NOT including the trailing `0x0000`.
    pub chars: Vec<u16>,
}

impl Utf16String {
    pub fn new(chars: Vec<u16>) -> Self {
        Self { chars }
    }

    pub fn from_str(s: &str) -> Self {
        Self {
            chars: s.encode_utf16().collect(),
        }
    }

    /// `cch` as placed on the wire (includes the NUL terminator).
    /// Saturates at `u32::MAX` — callers MUST pair with a cap check.
    #[must_use]
    pub fn wire_cch(&self) -> u32 {
        u32::try_from(self.chars.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1)
    }

    /// Byte length on the wire. Uses saturating arithmetic — callers
    /// must pair with a cch cap check.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        self.chars
            .len()
            .saturating_add(1)
            .saturating_mul(2)
    }
}

/// multisz UTF-16LE (double-NUL terminated sequence of NUL-terminated strings).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Utf16Multisz {
    /// Raw code units including every trailing NUL. The final `0x0000` is
    /// the overall terminator; the preceding ones separate items.
    pub raw: Vec<u16>,
}

impl Utf16Multisz {
    pub fn from_items<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut raw: Vec<u16> = Vec::new();
        for s in items {
            raw.extend(s.as_ref().encode_utf16());
            raw.push(0);
        }
        // Final terminator (double-NUL): if there was at least one item we
        // already pushed one NUL; push one more to close the multisz.
        raw.push(0);
        Self { raw }
    }

    /// `cch` as placed on the wire (equals `raw.len()`). Saturates at
    /// `u32::MAX` — callers MUST pair this with the per-field
    /// `MAX_*_CHARS` cap check, otherwise a silent truncation could
    /// bypass the cap validation.
    #[must_use]
    pub fn wire_cch(&self) -> u32 {
        u32::try_from(self.raw.len()).unwrap_or(u32::MAX)
    }

    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        self.raw.len().saturating_mul(2)
    }
}

/// Encode a UTF-16LE NUL-terminated string. `cch` from the wire is ignored
/// here; the caller writes it separately.
pub(crate) fn encode_utf16_cstring(
    s: &Utf16String,
    dst: &mut WriteCursor<'_>,
) -> EncodeResult<()> {
    for &c in &s.chars {
        dst.write_u16_le(c, "Utf16String::char")?;
    }
    dst.write_u16_le(0, "Utf16String::NUL")?;
    Ok(())
}

/// Decode a UTF-16LE NUL-terminated string given its wire `cch` (count of
/// UTF-16 code units including the terminating NUL).
pub(crate) fn decode_utf16_cstring(
    src: &mut ReadCursor<'_>,
    cch: u32,
    context: &'static str,
    cap_chars: u32,
) -> DecodeResult<Utf16String> {
    if cch == 0 {
        return Err(DecodeError::invalid_value(context, "cch (must be >= 1)"));
    }
    if cch > cap_chars {
        return Err(DecodeError::invalid_value(context, "cch > cap"));
    }
    // Safe: cap_chars fits in u32 and cap_chars * 2 fits in usize on all
    // reasonable targets; use checked_mul anyway.
    let byte_len = (cch as usize)
        .checked_mul(2)
        .ok_or_else(|| DecodeError::invalid_value(context, "cch*2 overflow"))?;
    let bytes = src.read_slice(byte_len, context)?;
    let mut chars = Vec::with_capacity(cch as usize - 1);
    // Iterate pairs of bytes. The last code unit must be NUL; the rest
    // accumulate into `chars`.
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let c = u16::from_le_bytes([pair[0], pair[1]]);
        if i == cch as usize - 1 {
            if c != 0 {
                return Err(DecodeError::invalid_value(context, "missing NUL terminator"));
            }
        } else {
            chars.push(c);
        }
    }
    Ok(Utf16String { chars })
}

/// Encode a UTF-16LE multisz.
pub(crate) fn encode_utf16_multisz(
    m: &Utf16Multisz,
    dst: &mut WriteCursor<'_>,
) -> EncodeResult<()> {
    for &c in &m.raw {
        dst.write_u16_le(c, "Utf16Multisz::char")?;
    }
    Ok(())
}

/// Decode a UTF-16LE multisz of length `cch` code units.
pub(crate) fn decode_utf16_multisz(
    src: &mut ReadCursor<'_>,
    cch: u32,
    context: &'static str,
    cap_chars: u32,
) -> DecodeResult<Utf16Multisz> {
    if cch > cap_chars {
        return Err(DecodeError::invalid_value(context, "cch > cap"));
    }
    let byte_len = (cch as usize)
        .checked_mul(2)
        .ok_or_else(|| DecodeError::invalid_value(context, "cch*2 overflow"))?;
    let bytes = src.read_slice(byte_len, context)?;
    let mut raw = Vec::with_capacity(cch as usize);
    for i in 0..(cch as usize) {
        raw.push(u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]));
    }
    Ok(Utf16Multisz { raw })
}

// =============================================================================
// Capability exchange (MS-RDPEUSB 2.2.3)
// =============================================================================

/// `RIM_EXCHANGE_CAPABILITY_REQUEST`. MS-RDPEUSB 2.2.3.1
///
/// Server -> client. 16 bytes. Header uses `STREAM_ID_NONE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RimExchangeCapabilityRequest {
    pub header: SharedMsgHeader,
    pub capability_value: u32,
}

impl RimExchangeCapabilityRequest {
    pub const WIRE_SIZE: usize = 16;

    pub fn new(message_id: u32) -> Self {
        Self {
            header: SharedMsgHeader::request(
                IID_CAPABILITY_NEGOTIATOR,
                Mask::StreamIdNone,
                message_id,
                FN_RIM_EXCHANGE_CAPABILITY_REQUEST,
            ),
            capability_value: RIM_CAPABILITY_VERSION_01,
        }
    }
}

impl Encode for RimExchangeCapabilityRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.mask != Mask::StreamIdNone
            || self.header.interface_id != IID_CAPABILITY_NEGOTIATOR
            || self.header.function_id != Some(FN_RIM_EXCHANGE_CAPABILITY_REQUEST)
        {
            return Err(EncodeError::invalid_value(
                "RimExchangeCapabilityRequest",
                "header",
            ));
        }
        if self.capability_value != RIM_CAPABILITY_VERSION_01 {
            return Err(EncodeError::invalid_value(
                "RimExchangeCapabilityRequest",
                "CapabilityValue",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.capability_value, "RIM_EXCH_REQ::CapabilityValue")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RimExchangeCapabilityRequest"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for RimExchangeCapabilityRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_request(src)?;
        if header.mask != Mask::StreamIdNone {
            return Err(DecodeError::unexpected_value(
                "RimExchangeCapabilityRequest",
                "Mask",
                "not STREAM_ID_NONE",
            ));
        }
        if header.interface_id != IID_CAPABILITY_NEGOTIATOR {
            return Err(DecodeError::unexpected_value(
                "RimExchangeCapabilityRequest",
                "InterfaceId",
                "!= 0",
            ));
        }
        if header.function_id != Some(FN_RIM_EXCHANGE_CAPABILITY_REQUEST) {
            return Err(DecodeError::unexpected_value(
                "RimExchangeCapabilityRequest",
                "FunctionId",
                "!= 0x100",
            ));
        }
        let capability_value = src.read_u32_le("RIM_EXCH_REQ::CapabilityValue")?;
        if capability_value != RIM_CAPABILITY_VERSION_01 {
            return Err(DecodeError::invalid_value(
                "RimExchangeCapabilityRequest",
                "CapabilityValue",
            ));
        }
        Ok(Self {
            header,
            capability_value,
        })
    }
}

/// `RIM_EXCHANGE_CAPABILITY_RESPONSE`. MS-RDPEUSB 2.2.3.2
///
/// Client -> server. 16 bytes. Header is 8 bytes (`STREAM_ID_NONE`, no
/// FunctionId -- the one exception in MS-RDPEUSB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RimExchangeCapabilityResponse {
    /// Must be `STREAM_ID_NONE`, 8-byte header (no `FunctionId`).
    pub header: SharedMsgHeader,
    pub capability_value: u32,
    pub result: u32,
}

impl RimExchangeCapabilityResponse {
    pub const WIRE_SIZE: usize = 16;

    /// Build a response echoing the request's `MessageId`.
    pub fn new(message_id: u32, result: u32) -> Self {
        Self {
            header: SharedMsgHeader {
                interface_id: IID_CAPABILITY_NEGOTIATOR,
                mask: Mask::StreamIdNone,
                message_id,
                function_id: None,
            },
            capability_value: RIM_CAPABILITY_VERSION_01,
            result,
        }
    }
}

impl Encode for RimExchangeCapabilityResponse {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.mask != Mask::StreamIdNone || self.header.function_id.is_some() {
            return Err(EncodeError::invalid_value(
                "RimExchangeCapabilityResponse",
                "header (STREAM_ID_NONE, no FunctionId required)",
            ));
        }
        if self.capability_value != RIM_CAPABILITY_VERSION_01 {
            return Err(EncodeError::invalid_value(
                "RimExchangeCapabilityResponse",
                "CapabilityValue",
            ));
        }
        // Header: 8 bytes (STREAM_ID_NONE, no FunctionId per 2.2.3.2).
        let word0 = (self.header.interface_id & SharedMsgHeader::INTERFACE_ID_MASK)
            | ((Mask::StreamIdNone.as_bits()) << 30);
        dst.write_u32_le(word0, "RIM_EXCH_RSP::Word0")?;
        dst.write_u32_le(self.header.message_id, "RIM_EXCH_RSP::MessageId")?;
        dst.write_u32_le(self.capability_value, "RIM_EXCH_RSP::CapabilityValue")?;
        dst.write_u32_le(self.result, "RIM_EXCH_RSP::Result")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RimExchangeCapabilityResponse"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for RimExchangeCapabilityResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_response(src)?;
        if header.mask != Mask::StreamIdNone {
            return Err(DecodeError::unexpected_value(
                "RimExchangeCapabilityResponse",
                "Mask",
                "not STREAM_ID_NONE",
            ));
        }
        if header.interface_id != IID_CAPABILITY_NEGOTIATOR {
            return Err(DecodeError::invalid_value(
                "RimExchangeCapabilityResponse",
                "InterfaceId",
            ));
        }
        let capability_value = src.read_u32_le("RIM_EXCH_RSP::CapabilityValue")?;
        let result = src.read_u32_le("RIM_EXCH_RSP::Result")?;
        if capability_value != RIM_CAPABILITY_VERSION_01 {
            return Err(DecodeError::invalid_value(
                "RimExchangeCapabilityResponse",
                "CapabilityValue",
            ));
        }
        Ok(Self {
            header,
            capability_value,
            result,
        })
    }
}

// =============================================================================
// Channel notification (MS-RDPEUSB 2.2.5)
// =============================================================================

/// `CHANNEL_CREATED`. MS-RDPEUSB 2.2.5.1 — 24 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelCreated {
    pub header: SharedMsgHeader,
    pub major_version: u32,
    pub minor_version: u32,
    pub capabilities: u32,
}

impl ChannelCreated {
    pub const WIRE_SIZE: usize = 24;

    /// Server-side (InterfaceId = 2). MS-RDPEUSB 2.2.5.1
    pub fn server(message_id: u32) -> Self {
        Self::build(IID_CHANNEL_NOTIFICATION_S2C, message_id)
    }

    /// Client-side (InterfaceId = 3). MS-RDPEUSB 2.2.5.1
    pub fn client(message_id: u32) -> Self {
        Self::build(IID_CHANNEL_NOTIFICATION_C2S, message_id)
    }

    fn build(interface_id: u32, message_id: u32) -> Self {
        Self {
            header: SharedMsgHeader::request(
                interface_id,
                Mask::StreamIdProxy,
                message_id,
                FN_CHANNEL_CREATED,
            ),
            major_version: 1,
            minor_version: 0,
            capabilities: 0,
        }
    }

    /// Validate version and capability fields (MUST be `1`/`0`/`0`).
    pub fn validate_version(&self) -> Result<(), &'static str> {
        if self.major_version != 1 {
            return Err("MajorVersion != 1");
        }
        if self.minor_version != 0 {
            return Err("MinorVersion != 0");
        }
        if self.capabilities != 0 {
            return Err("Capabilities != 0");
        }
        Ok(())
    }
}

impl Encode for ChannelCreated {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.mask != Mask::StreamIdProxy
            || self.header.function_id != Some(FN_CHANNEL_CREATED)
        {
            return Err(EncodeError::invalid_value("ChannelCreated", "header"));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.major_version, "CHANNEL_CREATED::MajorVersion")?;
        dst.write_u32_le(self.minor_version, "CHANNEL_CREATED::MinorVersion")?;
        dst.write_u32_le(self.capabilities, "CHANNEL_CREATED::Capabilities")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ChannelCreated"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for ChannelCreated {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_request(src)?;
        if header.function_id != Some(FN_CHANNEL_CREATED) {
            return Err(DecodeError::invalid_value("ChannelCreated", "FunctionId"));
        }
        let major_version = src.read_u32_le("CHANNEL_CREATED::MajorVersion")?;
        let minor_version = src.read_u32_le("CHANNEL_CREATED::MinorVersion")?;
        let capabilities = src.read_u32_le("CHANNEL_CREATED::Capabilities")?;
        Ok(Self {
            header,
            major_version,
            minor_version,
            capabilities,
        })
    }
}

// =============================================================================
// Device Sink Interface (MS-RDPEUSB 2.2.4)
// =============================================================================

/// `ADD_VIRTUAL_CHANNEL`. MS-RDPEUSB 2.2.4.1 — 12-byte header only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddVirtualChannel {
    pub header: SharedMsgHeader,
}

impl AddVirtualChannel {
    pub const WIRE_SIZE: usize = 12;

    pub fn new(message_id: u32) -> Self {
        Self {
            header: SharedMsgHeader::request(
                IID_DEVICE_SINK,
                Mask::StreamIdProxy,
                message_id,
                FN_ADD_VIRTUAL_CHANNEL,
            ),
        }
    }
}

impl Encode for AddVirtualChannel {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.interface_id != IID_DEVICE_SINK
            || self.header.mask != Mask::StreamIdProxy
            || self.header.function_id != Some(FN_ADD_VIRTUAL_CHANNEL)
        {
            return Err(EncodeError::invalid_value("AddVirtualChannel", "header"));
        }
        self.header.encode(dst)
    }
    fn name(&self) -> &'static str {
        "AddVirtualChannel"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for AddVirtualChannel {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_request(src)?;
        if header.function_id != Some(FN_ADD_VIRTUAL_CHANNEL) {
            return Err(DecodeError::invalid_value("AddVirtualChannel", "FunctionId"));
        }
        Ok(Self { header })
    }
}

/// `USB_DEVICE_CAPABILITIES`. MS-RDPEUSB 2.2.11 — 28-byte fixed structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbDeviceCapabilities {
    /// MUST be 28 (`0x0000001C`).
    pub cb_size: u32,
    /// 0x00 / 0x01 / 0x02.
    pub usb_bus_interface_version: u32,
    /// MUST be `0x500` or `0x600`.
    pub usbdi_version: u32,
    /// `0x0100` / `0x0110` / `0x0200`.
    pub supported_usb_version: u32,
    /// MUST be 0.
    pub hcd_capabilities: u32,
    /// 0 = full speed, 1 = high speed. If `usb_bus_interface_version == 0`,
    /// this MUST be 0.
    pub device_is_high_speed: u32,
    /// 0 = no isoch no-ack support; else ms, in `[10, 512]`.
    pub no_ack_isoch_write_jitter_buffer_size_in_ms: u32,
}

impl UsbDeviceCapabilities {
    pub const WIRE_SIZE: usize = 28;

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.cb_size != Self::WIRE_SIZE as u32 {
            return Err("CbSize != 28");
        }
        if self.usb_bus_interface_version > 2 {
            return Err("UsbBusInterfaceVersion invalid");
        }
        if self.usbdi_version != 0x0000_0500 && self.usbdi_version != 0x0000_0600 {
            return Err("USBDI_Version invalid");
        }
        if !matches!(self.supported_usb_version, 0x0100 | 0x0110 | 0x0200) {
            return Err("Supported_USB_Version invalid");
        }
        if self.hcd_capabilities != 0 {
            return Err("HcdCapabilities != 0");
        }
        if self.usb_bus_interface_version == 0 && self.device_is_high_speed != 0 {
            return Err("DeviceIsHighSpeed MUST be 0 when BusInterfaceVersion=0");
        }
        let noack = self.no_ack_isoch_write_jitter_buffer_size_in_ms;
        if noack != 0 && !(10..=512).contains(&noack) {
            return Err("NoAckIsochWriteJitterBufferSizeInMs out of range");
        }
        Ok(())
    }
}

impl Encode for UsbDeviceCapabilities {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        self.validate()
            .map_err(|_| EncodeError::invalid_value("UsbDeviceCapabilities", "validation"))?;
        dst.write_u32_le(self.cb_size, "USB_DEVICE_CAPABILITIES::CbSize")?;
        dst.write_u32_le(
            self.usb_bus_interface_version,
            "USB_DEVICE_CAPABILITIES::UsbBusInterfaceVersion",
        )?;
        dst.write_u32_le(self.usbdi_version, "USB_DEVICE_CAPABILITIES::USBDI_Version")?;
        dst.write_u32_le(
            self.supported_usb_version,
            "USB_DEVICE_CAPABILITIES::Supported_USB_Version",
        )?;
        dst.write_u32_le(
            self.hcd_capabilities,
            "USB_DEVICE_CAPABILITIES::HcdCapabilities",
        )?;
        dst.write_u32_le(
            self.device_is_high_speed,
            "USB_DEVICE_CAPABILITIES::DeviceIsHighSpeed",
        )?;
        dst.write_u32_le(
            self.no_ack_isoch_write_jitter_buffer_size_in_ms,
            "USB_DEVICE_CAPABILITIES::NoAckIsoch",
        )?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "UsbDeviceCapabilities"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for UsbDeviceCapabilities {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cb_size = src.read_u32_le("USB_DEVICE_CAPABILITIES::CbSize")?;
        let usb_bus_interface_version =
            src.read_u32_le("USB_DEVICE_CAPABILITIES::UsbBusInterfaceVersion")?;
        let usbdi_version = src.read_u32_le("USB_DEVICE_CAPABILITIES::USBDI_Version")?;
        let supported_usb_version =
            src.read_u32_le("USB_DEVICE_CAPABILITIES::Supported_USB_Version")?;
        let hcd_capabilities = src.read_u32_le("USB_DEVICE_CAPABILITIES::HcdCapabilities")?;
        let device_is_high_speed =
            src.read_u32_le("USB_DEVICE_CAPABILITIES::DeviceIsHighSpeed")?;
        let no_ack_isoch_write_jitter_buffer_size_in_ms =
            src.read_u32_le("USB_DEVICE_CAPABILITIES::NoAckIsoch")?;
        let value = Self {
            cb_size,
            usb_bus_interface_version,
            usbdi_version,
            supported_usb_version,
            hcd_capabilities,
            device_is_high_speed,
            no_ack_isoch_write_jitter_buffer_size_in_ms,
        };
        value.validate().map_err(|m| {
            DecodeError::invalid_value("UsbDeviceCapabilities", match m {
                "CbSize != 28" => "CbSize",
                "HcdCapabilities != 0" => "HcdCapabilities",
                "NoAckIsochWriteJitterBufferSizeInMs out of range" => "NoAckIsoch",
                _ => "validation",
            })
        })?;
        Ok(value)
    }
}

/// `ADD_DEVICE`. MS-RDPEUSB 2.2.4.2
///
/// Sent on the per-device DVC after it has been opened by the server in
/// response to `ADD_VIRTUAL_CHANNEL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddDevice {
    pub header: SharedMsgHeader,
    /// MUST be 1.
    pub num_usb_device: u32,
    /// Client-allocated `InterfaceId` for this device.
    pub usb_device: u32,
    pub device_instance_id: Utf16String,
    /// `None` when `cchHwIds == 0` (absent buffer — NOT empty buffer).
    pub hardware_ids: Option<Utf16Multisz>,
    /// `None` when `cchCompatIds == 0`.
    pub compatibility_ids: Option<Utf16Multisz>,
    pub container_id: Utf16String,
    pub usb_device_capabilities: UsbDeviceCapabilities,
}

impl AddDevice {
    /// Validate the `ContainerId` parses as a GUID and is not all-zero.
    /// Per MS-RDPEUSB 2.2.4.2 the all-zero GUID is forbidden.
    pub fn validate_container_id(&self) -> Result<(), &'static str> {
        // Convert UTF-16 to a (very small) ASCII representation. Canonical
        // form is "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".
        let s: alloc::string::String = char::decode_utf16(self.container_id.chars.iter().copied())
            .map(|r| r.unwrap_or('\u{FFFD}'))
            .collect();
        let trimmed = s.trim_matches(|c| c == '{' || c == '}');
        let hex_only: alloc::string::String =
            trimmed.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex_only.len() != 32 {
            return Err("ContainerId not a GUID");
        }
        if hex_only.chars().all(|c| c == '0') {
            return Err("ContainerId is all-zero GUID");
        }
        Ok(())
    }
}

impl Encode for AddDevice {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.interface_id != IID_DEVICE_SINK
            || self.header.mask != Mask::StreamIdProxy
            || self.header.function_id != Some(FN_ADD_DEVICE)
        {
            return Err(EncodeError::invalid_value("AddDevice", "header"));
        }
        if self.num_usb_device != 1 {
            return Err(EncodeError::invalid_value("AddDevice", "NumUsbDevice"));
        }
        if self.device_instance_id.wire_cch() > MAX_DEVICE_INSTANCE_ID_CHARS {
            return Err(EncodeError::invalid_value("AddDevice", "cchDeviceInstanceId"));
        }
        if let Some(h) = &self.hardware_ids {
            if h.wire_cch() > MAX_HARDWARE_IDS_CHARS {
                return Err(EncodeError::invalid_value("AddDevice", "cchHwIds"));
            }
        }
        if let Some(h) = &self.compatibility_ids {
            if h.wire_cch() > MAX_COMPATIBILITY_IDS_CHARS {
                return Err(EncodeError::invalid_value("AddDevice", "cchCompatIds"));
            }
        }
        if self.container_id.wire_cch() > MAX_CONTAINER_ID_CHARS {
            return Err(EncodeError::invalid_value("AddDevice", "cchContainerId"));
        }
        self.validate_container_id()
            .map_err(|_| EncodeError::invalid_value("AddDevice", "ContainerId"))?;
        self.usb_device_capabilities
            .validate()
            .map_err(|_| EncodeError::invalid_value("AddDevice", "UsbDeviceCapabilities"))?;

        self.header.encode(dst)?;
        dst.write_u32_le(self.num_usb_device, "ADD_DEVICE::NumUsbDevice")?;
        dst.write_u32_le(self.usb_device, "ADD_DEVICE::UsbDevice")?;

        dst.write_u32_le(
            self.device_instance_id.wire_cch(),
            "ADD_DEVICE::cchDeviceInstanceId",
        )?;
        encode_utf16_cstring(&self.device_instance_id, dst)?;

        match &self.hardware_ids {
            Some(m) => {
                dst.write_u32_le(m.wire_cch(), "ADD_DEVICE::cchHwIds")?;
                encode_utf16_multisz(m, dst)?;
            }
            None => dst.write_u32_le(0, "ADD_DEVICE::cchHwIds")?,
        }

        match &self.compatibility_ids {
            Some(m) => {
                dst.write_u32_le(m.wire_cch(), "ADD_DEVICE::cchCompatIds")?;
                encode_utf16_multisz(m, dst)?;
            }
            None => dst.write_u32_le(0, "ADD_DEVICE::cchCompatIds")?,
        }

        dst.write_u32_le(self.container_id.wire_cch(), "ADD_DEVICE::cchContainerId")?;
        encode_utf16_cstring(&self.container_id, dst)?;

        self.usb_device_capabilities.encode(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "AddDevice"
    }

    fn size(&self) -> usize {
        let mut n = SharedMsgHeader::REQUEST_SIZE;
        n += 4 + 4; // NumUsbDevice + UsbDevice
        n += 4 + self.device_instance_id.wire_bytes(); // cchDeviceInstanceId + str
        n += 4 + self.hardware_ids.as_ref().map(|m| m.wire_bytes()).unwrap_or(0);
        n += 4
            + self
                .compatibility_ids
                .as_ref()
                .map(|m| m.wire_bytes())
                .unwrap_or(0);
        n += 4 + self.container_id.wire_bytes();
        n += UsbDeviceCapabilities::WIRE_SIZE;
        n
    }
}

impl<'de> Decode<'de> for AddDevice {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_request(src)?;
        if header.function_id != Some(FN_ADD_DEVICE) {
            return Err(DecodeError::invalid_value("AddDevice", "FunctionId"));
        }
        let num_usb_device = src.read_u32_le("ADD_DEVICE::NumUsbDevice")?;
        if num_usb_device != 1 {
            return Err(DecodeError::invalid_value("AddDevice", "NumUsbDevice"));
        }
        let usb_device = src.read_u32_le("ADD_DEVICE::UsbDevice")?;

        let cch_did = src.read_u32_le("ADD_DEVICE::cchDeviceInstanceId")?;
        let device_instance_id = decode_utf16_cstring(
            src,
            cch_did,
            "ADD_DEVICE::DeviceInstanceId",
            MAX_DEVICE_INSTANCE_ID_CHARS,
        )?;

        let cch_hw = src.read_u32_le("ADD_DEVICE::cchHwIds")?;
        let hardware_ids = if cch_hw == 0 {
            None
        } else {
            Some(decode_utf16_multisz(
                src,
                cch_hw,
                "ADD_DEVICE::HardwareIds",
                MAX_HARDWARE_IDS_CHARS,
            )?)
        };

        let cch_ci = src.read_u32_le("ADD_DEVICE::cchCompatIds")?;
        let compatibility_ids = if cch_ci == 0 {
            None
        } else {
            Some(decode_utf16_multisz(
                src,
                cch_ci,
                "ADD_DEVICE::CompatibilityIds",
                MAX_COMPATIBILITY_IDS_CHARS,
            )?)
        };

        let cch_cont = src.read_u32_le("ADD_DEVICE::cchContainerId")?;
        let container_id = decode_utf16_cstring(
            src,
            cch_cont,
            "ADD_DEVICE::ContainerId",
            MAX_CONTAINER_ID_CHARS,
        )?;

        let usb_device_capabilities = UsbDeviceCapabilities::decode(src)?;

        let value = Self {
            header,
            num_usb_device,
            usb_device,
            device_instance_id,
            hardware_ids,
            compatibility_ids,
            container_id,
            usb_device_capabilities,
        };
        value
            .validate_container_id()
            .map_err(|_| DecodeError::invalid_value("AddDevice", "ContainerId"))?;
        Ok(value)
    }
}

// =============================================================================
// USB Device Interface — Server -> Client (MS-RDPEUSB 2.2.6)
// =============================================================================

/// `CANCEL_REQUEST`. MS-RDPEUSB 2.2.6.1 — 16 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelRequest {
    pub header: SharedMsgHeader,
    pub request_id: u32,
}

impl CancelRequest {
    pub const WIRE_SIZE: usize = 16;
    pub fn new(usb_device: u32, message_id: u32, request_id: u32) -> Self {
        Self {
            header: SharedMsgHeader::request(
                usb_device,
                Mask::StreamIdProxy,
                message_id,
                FN_CANCEL_REQUEST,
            ),
            request_id,
        }
    }
}

impl Encode for CancelRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.function_id != Some(FN_CANCEL_REQUEST) {
            return Err(EncodeError::invalid_value("CancelRequest", "FunctionId"));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.request_id, "CANCEL_REQUEST::RequestId")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "CancelRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for CancelRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_request(src)?;
        if header.function_id != Some(FN_CANCEL_REQUEST) {
            return Err(DecodeError::invalid_value("CancelRequest", "FunctionId"));
        }
        let request_id = src.read_u32_le("CANCEL_REQUEST::RequestId")?;
        Ok(Self { header, request_id })
    }
}

/// `REGISTER_REQUEST_CALLBACK`. MS-RDPEUSB 2.2.6.2 — 16 or 20 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequestCallback {
    pub header: SharedMsgHeader,
    pub num_request_completion: u32,
    /// Present iff `num_request_completion >= 1`.
    pub request_completion: Option<u32>,
}

impl RegisterRequestCallback {
    pub fn new(usb_device: u32, message_id: u32, request_completion: u32) -> Self {
        Self {
            header: SharedMsgHeader::request(
                usb_device,
                Mask::StreamIdProxy,
                message_id,
                FN_REGISTER_REQUEST_CALLBACK,
            ),
            num_request_completion: 1,
            request_completion: Some(request_completion),
        }
    }
}

impl Encode for RegisterRequestCallback {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.function_id != Some(FN_REGISTER_REQUEST_CALLBACK) {
            return Err(EncodeError::invalid_value(
                "RegisterRequestCallback",
                "FunctionId",
            ));
        }
        match (self.num_request_completion, self.request_completion) {
            (0, None) => {}
            (n, Some(_)) if n >= 1 => {}
            _ => {
                return Err(EncodeError::invalid_value(
                    "RegisterRequestCallback",
                    "NumRequestCompletion/RequestCompletion",
                ));
            }
        }
        self.header.encode(dst)?;
        dst.write_u32_le(
            self.num_request_completion,
            "REGISTER::NumRequestCompletion",
        )?;
        if let Some(rc) = self.request_completion {
            dst.write_u32_le(rc, "REGISTER::RequestCompletion")?;
        }
        Ok(())
    }
    fn name(&self) -> &'static str {
        "RegisterRequestCallback"
    }
    fn size(&self) -> usize {
        SharedMsgHeader::REQUEST_SIZE + 4 + if self.request_completion.is_some() { 4 } else { 0 }
    }
}

impl<'de> Decode<'de> for RegisterRequestCallback {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_request(src)?;
        if header.function_id != Some(FN_REGISTER_REQUEST_CALLBACK) {
            return Err(DecodeError::invalid_value(
                "RegisterRequestCallback",
                "FunctionId",
            ));
        }
        let num_request_completion = src.read_u32_le("REGISTER::NumRequestCompletion")?;
        let request_completion = if num_request_completion == 0 {
            None
        } else {
            Some(src.read_u32_le("REGISTER::RequestCompletion")?)
        };
        Ok(Self {
            header,
            num_request_completion,
            request_completion,
        })
    }
}

// ── IO_CONTROL and INTERNAL_IO_CONTROL share layout ──

/// `IO_CONTROL`. MS-RDPEUSB 2.2.6.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoControl {
    pub header: SharedMsgHeader,
    pub io_control_code: u32,
    pub input_buffer: Vec<u8>,
    pub output_buffer_size: u32,
    pub request_id: u32,
}

/// `INTERNAL_IO_CONTROL`. MS-RDPEUSB 2.2.6.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalIoControl {
    pub header: SharedMsgHeader,
    pub io_control_code: u32,
    pub input_buffer: Vec<u8>,
    pub output_buffer_size: u32,
    pub request_id: u32,
}

fn encode_ioctl_like(
    header: &SharedMsgHeader,
    io_control_code: u32,
    input_buffer: &[u8],
    output_buffer_size: u32,
    request_id: u32,
    dst: &mut WriteCursor<'_>,
    expected_fid: u32,
    ctx: &'static str,
) -> EncodeResult<()> {
    if header.function_id != Some(expected_fid) {
        return Err(EncodeError::invalid_value(ctx, "FunctionId"));
    }
    if input_buffer.len() as u64 > MAX_IOCTL_BUFFER_SIZE as u64 {
        return Err(EncodeError::invalid_value(ctx, "InputBufferSize > cap"));
    }
    if output_buffer_size > MAX_IOCTL_BUFFER_SIZE {
        return Err(EncodeError::invalid_value(ctx, "OutputBufferSize > cap"));
    }
    header.encode(dst)?;
    dst.write_u32_le(io_control_code, "IoControl::IoControlCode")?;
    dst.write_u32_le(input_buffer.len() as u32, "IoControl::InputBufferSize")?;
    dst.write_slice(input_buffer, "IoControl::InputBuffer")?;
    dst.write_u32_le(output_buffer_size, "IoControl::OutputBufferSize")?;
    dst.write_u32_le(request_id, "IoControl::RequestId")?;
    Ok(())
}

fn decode_ioctl_like(
    src: &mut ReadCursor<'_>,
    expected_fid: u32,
    ctx: &'static str,
) -> DecodeResult<(SharedMsgHeader, u32, Vec<u8>, u32, u32)> {
    let header = SharedMsgHeader::decode_request(src)?;
    if header.function_id != Some(expected_fid) {
        return Err(DecodeError::invalid_value(ctx, "FunctionId"));
    }
    let io_control_code = src.read_u32_le("IoControl::IoControlCode")?;
    let input_buffer_size = src.read_u32_le("IoControl::InputBufferSize")?;
    if input_buffer_size > MAX_IOCTL_BUFFER_SIZE {
        return Err(DecodeError::invalid_value(ctx, "InputBufferSize > cap"));
    }
    let input = src
        .read_slice(input_buffer_size as usize, "IoControl::InputBuffer")?
        .to_vec();
    let output_buffer_size = src.read_u32_le("IoControl::OutputBufferSize")?;
    if output_buffer_size > MAX_IOCTL_BUFFER_SIZE {
        return Err(DecodeError::invalid_value(ctx, "OutputBufferSize > cap"));
    }
    let request_id = src.read_u32_le("IoControl::RequestId")?;
    Ok((header, io_control_code, input, output_buffer_size, request_id))
}

impl Encode for IoControl {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        encode_ioctl_like(
            &self.header,
            self.io_control_code,
            &self.input_buffer,
            self.output_buffer_size,
            self.request_id,
            dst,
            FN_IO_CONTROL,
            "IoControl",
        )
    }
    fn name(&self) -> &'static str {
        "IoControl"
    }
    fn size(&self) -> usize {
        SharedMsgHeader::REQUEST_SIZE + 4 + 4 + self.input_buffer.len() + 4 + 4
    }
}
impl<'de> Decode<'de> for IoControl {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (header, io_control_code, input_buffer, output_buffer_size, request_id) =
            decode_ioctl_like(src, FN_IO_CONTROL, "IoControl")?;
        Ok(Self {
            header,
            io_control_code,
            input_buffer,
            output_buffer_size,
            request_id,
        })
    }
}

impl Encode for InternalIoControl {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        encode_ioctl_like(
            &self.header,
            self.io_control_code,
            &self.input_buffer,
            self.output_buffer_size,
            self.request_id,
            dst,
            FN_INTERNAL_IO_CONTROL,
            "InternalIoControl",
        )
    }
    fn name(&self) -> &'static str {
        "InternalIoControl"
    }
    fn size(&self) -> usize {
        SharedMsgHeader::REQUEST_SIZE + 4 + 4 + self.input_buffer.len() + 4 + 4
    }
}
impl<'de> Decode<'de> for InternalIoControl {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (header, io_control_code, input_buffer, output_buffer_size, request_id) =
            decode_ioctl_like(src, FN_INTERNAL_IO_CONTROL, "InternalIoControl")?;
        Ok(Self {
            header,
            io_control_code,
            input_buffer,
            output_buffer_size,
            request_id,
        })
    }
}

/// `QUERY_DEVICE_TEXT`. MS-RDPEUSB 2.2.6.5 — 20 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDeviceText {
    pub header: SharedMsgHeader,
    pub text_type: u32,
    pub locale_id: u32,
}

impl QueryDeviceText {
    pub const WIRE_SIZE: usize = 20;
}

impl Encode for QueryDeviceText {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.function_id != Some(FN_QUERY_DEVICE_TEXT) {
            return Err(EncodeError::invalid_value("QueryDeviceText", "FunctionId"));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.text_type, "QUERY_DEVICE_TEXT::TextType")?;
        dst.write_u32_le(self.locale_id, "QUERY_DEVICE_TEXT::LocaleId")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "QueryDeviceText"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for QueryDeviceText {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_request(src)?;
        if header.function_id != Some(FN_QUERY_DEVICE_TEXT) {
            return Err(DecodeError::invalid_value("QueryDeviceText", "FunctionId"));
        }
        let text_type = src.read_u32_le("QUERY_DEVICE_TEXT::TextType")?;
        let locale_id = src.read_u32_le("QUERY_DEVICE_TEXT::LocaleId")?;
        Ok(Self {
            header,
            text_type,
            locale_id,
        })
    }
}

/// `QUERY_DEVICE_TEXT_RSP`. MS-RDPEUSB 2.2.6.6
///
/// 8-byte response header (`STREAM_ID_STUB`, no FunctionId), then
/// `cchDeviceDescription`, optional UTF-16 string, and `HResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDeviceTextRsp {
    pub header: SharedMsgHeader,
    /// `None` iff `cchDeviceDescription == 0`.
    pub device_description: Option<Utf16String>,
    pub h_result: u32,
}

impl Encode for QueryDeviceTextRsp {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.mask != Mask::StreamIdStub || self.header.function_id.is_some() {
            return Err(EncodeError::invalid_value(
                "QueryDeviceTextRsp",
                "header (STREAM_ID_STUB, no FunctionId)",
            ));
        }
        // Write 8-byte response header manually.
        let word0 = (self.header.interface_id & SharedMsgHeader::INTERFACE_ID_MASK)
            | ((Mask::StreamIdStub.as_bits()) << 30);
        dst.write_u32_le(word0, "QUERY_DEVICE_TEXT_RSP::Word0")?;
        dst.write_u32_le(self.header.message_id, "QUERY_DEVICE_TEXT_RSP::MessageId")?;

        match &self.device_description {
            Some(s) => {
                if s.wire_cch() > MAX_DEVICE_DESCRIPTION_CHARS {
                    return Err(EncodeError::invalid_value(
                        "QueryDeviceTextRsp",
                        "cchDeviceDescription > cap",
                    ));
                }
                dst.write_u32_le(s.wire_cch(), "QUERY_DEVICE_TEXT_RSP::cch")?;
                encode_utf16_cstring(s, dst)?;
            }
            None => {
                dst.write_u32_le(0, "QUERY_DEVICE_TEXT_RSP::cch")?;
            }
        }

        dst.write_u32_le(self.h_result, "QUERY_DEVICE_TEXT_RSP::HResult")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "QueryDeviceTextRsp"
    }

    fn size(&self) -> usize {
        let mut n = SharedMsgHeader::RESPONSE_SIZE + 4;
        if let Some(s) = &self.device_description {
            n += s.wire_bytes();
        }
        n += 4;
        n
    }
}

impl<'de> Decode<'de> for QueryDeviceTextRsp {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_response(src)?;
        if header.mask != Mask::StreamIdStub {
            return Err(DecodeError::unexpected_value(
                "QueryDeviceTextRsp",
                "Mask",
                "not STREAM_ID_STUB",
            ));
        }
        let cch = src.read_u32_le("QUERY_DEVICE_TEXT_RSP::cch")?;
        let device_description = if cch == 0 {
            None
        } else {
            Some(decode_utf16_cstring(
                src,
                cch,
                "QUERY_DEVICE_TEXT_RSP::DeviceDescription",
                MAX_DEVICE_DESCRIPTION_CHARS,
            )?)
        };
        let h_result = src.read_u32_le("QUERY_DEVICE_TEXT_RSP::HResult")?;
        Ok(Self {
            header,
            device_description,
            h_result,
        })
    }
}

/// `TRANSFER_IN_REQUEST`. MS-RDPEUSB 2.2.6.7
///
/// `ts_urb` is kept as raw bytes at the PDU layer. Callers parse it with
/// [`crate::ts_urb::TsUrb::decode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferInRequest {
    pub header: SharedMsgHeader,
    pub cb_ts_urb: u32,
    pub ts_urb: Vec<u8>,
    pub output_buffer_size: u32,
}

impl Encode for TransferInRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.function_id != Some(FN_TRANSFER_IN_REQUEST) {
            return Err(EncodeError::invalid_value("TransferInRequest", "FunctionId"));
        }
        if self.cb_ts_urb != self.ts_urb.len() as u32 {
            return Err(EncodeError::invalid_value("TransferInRequest", "CbTsUrb"));
        }
        if self.cb_ts_urb > MAX_CB_TS_URB {
            return Err(EncodeError::invalid_value("TransferInRequest", "CbTsUrb > cap"));
        }
        if self.output_buffer_size > MAX_TRANSFER_OUTPUT_BUFFER_SIZE {
            return Err(EncodeError::invalid_value(
                "TransferInRequest",
                "OutputBufferSize > cap",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.cb_ts_urb, "TRANSFER_IN_REQUEST::CbTsUrb")?;
        dst.write_slice(&self.ts_urb, "TRANSFER_IN_REQUEST::TsUrb")?;
        dst.write_u32_le(
            self.output_buffer_size,
            "TRANSFER_IN_REQUEST::OutputBufferSize",
        )?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TransferInRequest"
    }
    fn size(&self) -> usize {
        SharedMsgHeader::REQUEST_SIZE + 4 + self.ts_urb.len() + 4
    }
}

impl<'de> Decode<'de> for TransferInRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_request(src)?;
        if header.function_id != Some(FN_TRANSFER_IN_REQUEST) {
            return Err(DecodeError::invalid_value("TransferInRequest", "FunctionId"));
        }
        let cb_ts_urb = src.read_u32_le("TRANSFER_IN_REQUEST::CbTsUrb")?;
        if cb_ts_urb < 8 || cb_ts_urb > MAX_CB_TS_URB {
            return Err(DecodeError::invalid_value("TransferInRequest", "CbTsUrb"));
        }
        let ts_urb = src
            .read_slice(cb_ts_urb as usize, "TRANSFER_IN_REQUEST::TsUrb")?
            .to_vec();
        // Verify the TS_URB_HEADER.Size field (first u16) matches CbTsUrb.
        let urb_size = u16::from_le_bytes([ts_urb[0], ts_urb[1]]) as u32;
        if urb_size != cb_ts_urb {
            return Err(DecodeError::invalid_value(
                "TransferInRequest",
                "TS_URB_HEADER.Size != CbTsUrb",
            ));
        }
        let output_buffer_size = src.read_u32_le("TRANSFER_IN_REQUEST::OutputBufferSize")?;
        if output_buffer_size > MAX_TRANSFER_OUTPUT_BUFFER_SIZE {
            return Err(DecodeError::invalid_value(
                "TransferInRequest",
                "OutputBufferSize > cap",
            ));
        }
        Ok(Self {
            header,
            cb_ts_urb,
            ts_urb,
            output_buffer_size,
        })
    }
}

/// `TRANSFER_OUT_REQUEST`. MS-RDPEUSB 2.2.6.8
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferOutRequest {
    pub header: SharedMsgHeader,
    pub cb_ts_urb: u32,
    pub ts_urb: Vec<u8>,
    pub output_buffer_size: u32,
    pub output_buffer: Vec<u8>,
}

impl Encode for TransferOutRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.function_id != Some(FN_TRANSFER_OUT_REQUEST) {
            return Err(EncodeError::invalid_value("TransferOutRequest", "FunctionId"));
        }
        if self.cb_ts_urb != self.ts_urb.len() as u32 {
            return Err(EncodeError::invalid_value("TransferOutRequest", "CbTsUrb"));
        }
        if self.output_buffer_size != self.output_buffer.len() as u32 {
            return Err(EncodeError::invalid_value(
                "TransferOutRequest",
                "OutputBufferSize != buffer.len()",
            ));
        }
        if self.cb_ts_urb > MAX_CB_TS_URB
            || self.output_buffer_size > MAX_TRANSFER_OUTPUT_BUFFER_SIZE
        {
            return Err(EncodeError::invalid_value("TransferOutRequest", "cap"));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.cb_ts_urb, "TRANSFER_OUT_REQUEST::CbTsUrb")?;
        dst.write_slice(&self.ts_urb, "TRANSFER_OUT_REQUEST::TsUrb")?;
        dst.write_u32_le(
            self.output_buffer_size,
            "TRANSFER_OUT_REQUEST::OutputBufferSize",
        )?;
        dst.write_slice(&self.output_buffer, "TRANSFER_OUT_REQUEST::OutputBuffer")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TransferOutRequest"
    }
    fn size(&self) -> usize {
        SharedMsgHeader::REQUEST_SIZE + 4 + self.ts_urb.len() + 4 + self.output_buffer.len()
    }
}

impl<'de> Decode<'de> for TransferOutRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_request(src)?;
        if header.function_id != Some(FN_TRANSFER_OUT_REQUEST) {
            return Err(DecodeError::invalid_value("TransferOutRequest", "FunctionId"));
        }
        let cb_ts_urb = src.read_u32_le("TRANSFER_OUT_REQUEST::CbTsUrb")?;
        if cb_ts_urb < 8 || cb_ts_urb > MAX_CB_TS_URB {
            return Err(DecodeError::invalid_value("TransferOutRequest", "CbTsUrb"));
        }
        let ts_urb = src
            .read_slice(cb_ts_urb as usize, "TRANSFER_OUT_REQUEST::TsUrb")?
            .to_vec();
        let urb_size = u16::from_le_bytes([ts_urb[0], ts_urb[1]]) as u32;
        if urb_size != cb_ts_urb {
            return Err(DecodeError::invalid_value(
                "TransferOutRequest",
                "TS_URB_HEADER.Size != CbTsUrb",
            ));
        }
        let output_buffer_size = src.read_u32_le("TRANSFER_OUT_REQUEST::OutputBufferSize")?;
        if output_buffer_size > MAX_TRANSFER_OUTPUT_BUFFER_SIZE {
            return Err(DecodeError::invalid_value(
                "TransferOutRequest",
                "OutputBufferSize > cap",
            ));
        }
        let output_buffer = src
            .read_slice(output_buffer_size as usize, "TRANSFER_OUT_REQUEST::OutputBuffer")?
            .to_vec();
        Ok(Self {
            header,
            cb_ts_urb,
            ts_urb,
            output_buffer_size,
            output_buffer,
        })
    }
}

/// `RETRACT_DEVICE`. MS-RDPEUSB 2.2.6.9 — 16 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetractDevice {
    pub header: SharedMsgHeader,
    pub reason: u32,
}

impl RetractDevice {
    pub const WIRE_SIZE: usize = 16;
}

impl Encode for RetractDevice {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.function_id != Some(FN_RETRACT_DEVICE) {
            return Err(EncodeError::invalid_value("RetractDevice", "FunctionId"));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.reason, "RETRACT_DEVICE::Reason")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "RetractDevice"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for RetractDevice {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_request(src)?;
        if header.function_id != Some(FN_RETRACT_DEVICE) {
            return Err(DecodeError::invalid_value("RetractDevice", "FunctionId"));
        }
        let reason = src.read_u32_le("RETRACT_DEVICE::Reason")?;
        Ok(Self { header, reason })
    }
}

// =============================================================================
// Request Completion Interface (MS-RDPEUSB 2.2.7) — Client -> Server
// =============================================================================

/// `IOCONTROL_COMPLETION`. MS-RDPEUSB 2.2.7.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoControlCompletion {
    pub header: SharedMsgHeader,
    pub request_id: u32,
    pub h_result: u32,
    pub information: u32,
    pub output_buffer_size: u32,
    pub output_buffer: Vec<u8>,
}

impl IoControlCompletion {
    /// Validate the §2.2.7.1 `OutputBufferSize` rules. Returns `Err` on violation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if hresult_is_success(self.h_result) {
            if self.output_buffer_size != self.information {
                return Err("success: OutputBufferSize != Information");
            }
        } else if self.h_result == HRESULT_FROM_WIN32_ERROR_INSUFFICIENT_BUFFER {
            // Caller-controlled equality with request.OutputBufferSize is not
            // verifiable here; just accept.
        } else if self.output_buffer_size != 0 {
            return Err("error: OutputBufferSize must be 0");
        }
        if self.output_buffer.len() as u64 != self.output_buffer_size as u64 {
            return Err("OutputBuffer.len() != OutputBufferSize");
        }
        Ok(())
    }
}

impl Encode for IoControlCompletion {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.function_id != Some(FN_IOCONTROL_COMPLETION) {
            return Err(EncodeError::invalid_value(
                "IoControlCompletion",
                "FunctionId",
            ));
        }
        self.validate()
            .map_err(|_| EncodeError::invalid_value("IoControlCompletion", "rules"))?;
        self.header.encode(dst)?;
        dst.write_u32_le(self.request_id, "IOCONTROL_COMPLETION::RequestId")?;
        dst.write_u32_le(self.h_result, "IOCONTROL_COMPLETION::HResult")?;
        dst.write_u32_le(self.information, "IOCONTROL_COMPLETION::Information")?;
        dst.write_u32_le(
            self.output_buffer_size,
            "IOCONTROL_COMPLETION::OutputBufferSize",
        )?;
        dst.write_slice(&self.output_buffer, "IOCONTROL_COMPLETION::OutputBuffer")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "IoControlCompletion"
    }
    fn size(&self) -> usize {
        SharedMsgHeader::REQUEST_SIZE + 4 + 4 + 4 + 4 + self.output_buffer.len()
    }
}

impl<'de> Decode<'de> for IoControlCompletion {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_request(src)?;
        if header.function_id != Some(FN_IOCONTROL_COMPLETION) {
            return Err(DecodeError::invalid_value(
                "IoControlCompletion",
                "FunctionId",
            ));
        }
        let request_id = src.read_u32_le("IOCONTROL_COMPLETION::RequestId")?;
        let h_result = src.read_u32_le("IOCONTROL_COMPLETION::HResult")?;
        let information = src.read_u32_le("IOCONTROL_COMPLETION::Information")?;
        let output_buffer_size = src.read_u32_le("IOCONTROL_COMPLETION::OutputBufferSize")?;
        if output_buffer_size > MAX_IOCTL_BUFFER_SIZE {
            return Err(DecodeError::invalid_value(
                "IoControlCompletion",
                "OutputBufferSize > cap",
            ));
        }
        let output_buffer = src
            .read_slice(
                output_buffer_size as usize,
                "IOCONTROL_COMPLETION::OutputBuffer",
            )?
            .to_vec();
        let value = Self {
            header,
            request_id,
            h_result,
            information,
            output_buffer_size,
            output_buffer,
        };
        value
            .validate()
            .map_err(|_| DecodeError::invalid_value("IoControlCompletion", "rules"))?;
        Ok(value)
    }
}

/// `URB_COMPLETION`. MS-RDPEUSB 2.2.7.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrbCompletion {
    pub header: SharedMsgHeader,
    pub request_id: u32,
    pub cb_ts_urb_result: u32,
    pub ts_urb_result: Vec<u8>,
    pub h_result: u32,
    pub output_buffer_size: u32,
    pub output_buffer: Vec<u8>,
}

impl Encode for UrbCompletion {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.function_id != Some(FN_URB_COMPLETION) {
            return Err(EncodeError::invalid_value("UrbCompletion", "FunctionId"));
        }
        if self.cb_ts_urb_result != self.ts_urb_result.len() as u32 {
            return Err(EncodeError::invalid_value("UrbCompletion", "CbTsUrbResult"));
        }
        if self.cb_ts_urb_result > MAX_CB_TS_URB {
            return Err(EncodeError::invalid_value(
                "UrbCompletion",
                "CbTsUrbResult > cap",
            ));
        }
        if self.output_buffer_size != self.output_buffer.len() as u32 {
            return Err(EncodeError::invalid_value(
                "UrbCompletion",
                "OutputBufferSize != buffer.len()",
            ));
        }
        if self.output_buffer_size > MAX_TRANSFER_OUTPUT_BUFFER_SIZE {
            return Err(EncodeError::invalid_value(
                "UrbCompletion",
                "OutputBufferSize > cap",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.request_id, "URB_COMPLETION::RequestId")?;
        dst.write_u32_le(self.cb_ts_urb_result, "URB_COMPLETION::CbTsUrbResult")?;
        dst.write_slice(&self.ts_urb_result, "URB_COMPLETION::TsUrbResult")?;
        dst.write_u32_le(self.h_result, "URB_COMPLETION::HResult")?;
        dst.write_u32_le(self.output_buffer_size, "URB_COMPLETION::OutputBufferSize")?;
        dst.write_slice(&self.output_buffer, "URB_COMPLETION::OutputBuffer")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "UrbCompletion"
    }
    fn size(&self) -> usize {
        SharedMsgHeader::REQUEST_SIZE + 4 + 4 + self.ts_urb_result.len() + 4 + 4 + self.output_buffer.len()
    }
}

impl<'de> Decode<'de> for UrbCompletion {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_request(src)?;
        if header.function_id != Some(FN_URB_COMPLETION) {
            return Err(DecodeError::invalid_value("UrbCompletion", "FunctionId"));
        }
        let request_id = src.read_u32_le("URB_COMPLETION::RequestId")?;
        let cb_ts_urb_result = src.read_u32_le("URB_COMPLETION::CbTsUrbResult")?;
        if cb_ts_urb_result < 8 || cb_ts_urb_result > MAX_CB_TS_URB {
            return Err(DecodeError::invalid_value(
                "UrbCompletion",
                "CbTsUrbResult",
            ));
        }
        let ts_urb_result = src
            .read_slice(cb_ts_urb_result as usize, "URB_COMPLETION::TsUrbResult")?
            .to_vec();
        // TS_URB_RESULT_HEADER.Size (u16 @ 0) must equal CbTsUrbResult.
        let result_size = u16::from_le_bytes([ts_urb_result[0], ts_urb_result[1]]) as u32;
        if result_size != cb_ts_urb_result {
            return Err(DecodeError::invalid_value(
                "UrbCompletion",
                "TS_URB_RESULT_HEADER.Size",
            ));
        }
        let h_result = src.read_u32_le("URB_COMPLETION::HResult")?;
        let output_buffer_size = src.read_u32_le("URB_COMPLETION::OutputBufferSize")?;
        if output_buffer_size > MAX_TRANSFER_OUTPUT_BUFFER_SIZE {
            return Err(DecodeError::invalid_value(
                "UrbCompletion",
                "OutputBufferSize > cap",
            ));
        }
        let output_buffer = src
            .read_slice(output_buffer_size as usize, "URB_COMPLETION::OutputBuffer")?
            .to_vec();
        Ok(Self {
            header,
            request_id,
            cb_ts_urb_result,
            ts_urb_result,
            h_result,
            output_buffer_size,
            output_buffer,
        })
    }
}

/// `URB_COMPLETION_NO_DATA`. MS-RDPEUSB 2.2.7.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrbCompletionNoData {
    pub header: SharedMsgHeader,
    pub request_id: u32,
    pub cb_ts_urb_result: u32,
    pub ts_urb_result: Vec<u8>,
    pub h_result: u32,
    /// For `TRANSFER_OUT`: bytes actually sent. For `TRANSFER_IN`: MUST be 0.
    pub output_buffer_size: u32,
}

/// Source request kind used to validate `UrbCompletionNoData::output_buffer_size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrbCompletionSource {
    TransferIn,
    TransferOut,
}

impl UrbCompletionNoData {
    /// Validate §3.2.5.4.3 rule: if the request was TRANSFER_IN then
    /// `output_buffer_size` MUST be zero.
    pub fn validate_for_source(&self, source: UrbCompletionSource) -> Result<(), &'static str> {
        if source == UrbCompletionSource::TransferIn && self.output_buffer_size != 0 {
            return Err("TRANSFER_IN: OutputBufferSize must be 0");
        }
        Ok(())
    }
}

impl Encode for UrbCompletionNoData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.function_id != Some(FN_URB_COMPLETION_NO_DATA) {
            return Err(EncodeError::invalid_value(
                "UrbCompletionNoData",
                "FunctionId",
            ));
        }
        if self.cb_ts_urb_result != self.ts_urb_result.len() as u32
            || self.cb_ts_urb_result > MAX_CB_TS_URB
        {
            return Err(EncodeError::invalid_value(
                "UrbCompletionNoData",
                "CbTsUrbResult",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.request_id, "URB_COMPLETION_NO_DATA::RequestId")?;
        dst.write_u32_le(
            self.cb_ts_urb_result,
            "URB_COMPLETION_NO_DATA::CbTsUrbResult",
        )?;
        dst.write_slice(&self.ts_urb_result, "URB_COMPLETION_NO_DATA::TsUrbResult")?;
        dst.write_u32_le(self.h_result, "URB_COMPLETION_NO_DATA::HResult")?;
        dst.write_u32_le(
            self.output_buffer_size,
            "URB_COMPLETION_NO_DATA::OutputBufferSize",
        )?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "UrbCompletionNoData"
    }
    fn size(&self) -> usize {
        SharedMsgHeader::REQUEST_SIZE + 4 + 4 + self.ts_urb_result.len() + 4 + 4
    }
}

impl<'de> Decode<'de> for UrbCompletionNoData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = SharedMsgHeader::decode_request(src)?;
        if header.function_id != Some(FN_URB_COMPLETION_NO_DATA) {
            return Err(DecodeError::invalid_value(
                "UrbCompletionNoData",
                "FunctionId",
            ));
        }
        let request_id = src.read_u32_le("URB_COMPLETION_NO_DATA::RequestId")?;
        let cb_ts_urb_result = src.read_u32_le("URB_COMPLETION_NO_DATA::CbTsUrbResult")?;
        if cb_ts_urb_result < 8 || cb_ts_urb_result > MAX_CB_TS_URB {
            return Err(DecodeError::invalid_value(
                "UrbCompletionNoData",
                "CbTsUrbResult",
            ));
        }
        let ts_urb_result = src
            .read_slice(
                cb_ts_urb_result as usize,
                "URB_COMPLETION_NO_DATA::TsUrbResult",
            )?
            .to_vec();
        let result_size = u16::from_le_bytes([ts_urb_result[0], ts_urb_result[1]]) as u32;
        if result_size != cb_ts_urb_result {
            return Err(DecodeError::invalid_value(
                "UrbCompletionNoData",
                "TS_URB_RESULT_HEADER.Size",
            ));
        }
        let h_result = src.read_u32_le("URB_COMPLETION_NO_DATA::HResult")?;
        let output_buffer_size = src.read_u32_le("URB_COMPLETION_NO_DATA::OutputBufferSize")?;
        Ok(Self {
            header,
            request_id,
            cb_ts_urb_result,
            ts_urb_result,
            h_result,
            output_buffer_size,
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn encode_vec<E: Encode>(pdu: &E) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).expect("encode");
        assert_eq!(dst.pos(), pdu.size(), "size()/encode() mismatch for {}", pdu.name());
        buf
    }

    fn sample_caps() -> UsbDeviceCapabilities {
        UsbDeviceCapabilities {
            cb_size: 28,
            usb_bus_interface_version: 2,
            usbdi_version: 0x500,
            supported_usb_version: 0x0200,
            hcd_capabilities: 0,
            device_is_high_speed: 1,
            no_ack_isoch_write_jitter_buffer_size_in_ms: 0,
        }
    }

    fn sample_add_device() -> AddDevice {
        AddDevice {
            header: SharedMsgHeader::request(
                IID_DEVICE_SINK,
                Mask::StreamIdProxy,
                42,
                FN_ADD_DEVICE,
            ),
            num_usb_device: 1,
            usb_device: 0x0000_1000,
            device_instance_id: Utf16String::from_str("USB\\VID_1234&PID_5678\\6&1B2C3D4E"),
            hardware_ids: Some(Utf16Multisz::from_items(["USB\\VID_1234&PID_5678"])),
            compatibility_ids: Some(Utf16Multisz::from_items(["USB\\Class_03"])),
            container_id: Utf16String::from_str("{11112222-3333-4444-5555-666677778888}"),
            usb_device_capabilities: sample_caps(),
        }
    }

    #[test]
    fn header_max_interface_id_mask_2() {
        // Checklist §14: InterfaceId=0x3FFF_FFFF, Mask=2 => word=0xBFFF_FFFF.
        let mut buf = [0u8; 8];
        {
            let mut cur = WriteCursor::new(&mut buf);
            // Build via response() helper so Mask=STREAM_ID_STUB.
            let hdr = SharedMsgHeader {
                interface_id: 0x3FFF_FFFF,
                mask: Mask::StreamIdStub,
                message_id: 0,
                function_id: None,
            };
            hdr.encode(&mut cur).unwrap();
        }
        assert_eq!(buf[..4], [0xFF, 0xFF, 0xFF, 0xBF]);
    }

    #[test]
    fn header_interface_id_too_large_rejected() {
        let hdr = SharedMsgHeader::request(
            0x4000_0000,
            Mask::StreamIdProxy,
            1,
            FN_CANCEL_REQUEST,
        );
        let mut buf = [0u8; 12];
        let mut cur = WriteCursor::new(&mut buf);
        assert!(hdr.encode(&mut cur).is_err());
    }

    #[test]
    fn rim_exchange_capability_request_roundtrip() {
        let req = RimExchangeCapabilityRequest::new(1);
        let bytes = encode_vec(&req);
        assert_eq!(bytes.len(), 16);
        // First word: mask=0, interface=0 → all zeros.
        assert_eq!(&bytes[0..4], &[0, 0, 0, 0]);
        let mut src = ReadCursor::new(&bytes);
        let decoded = RimExchangeCapabilityRequest::decode(&mut src).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn rim_exchange_capability_response_roundtrip() {
        let rsp = RimExchangeCapabilityResponse::new(1, HRESULT_S_OK);
        let bytes = encode_vec(&rsp);
        assert_eq!(bytes.len(), 16);
        let mut src = ReadCursor::new(&bytes);
        let decoded = RimExchangeCapabilityResponse::decode(&mut src).unwrap();
        assert_eq!(decoded, rsp);
    }

    #[test]
    fn channel_created_server_and_client_roundtrip() {
        let server = ChannelCreated::server(7);
        let bytes = encode_vec(&server);
        assert_eq!(bytes.len(), 24);
        // Leading word: interface=2, mask=1 → 0x40000002 LE = 02 00 00 40.
        assert_eq!(&bytes[0..4], &[0x02, 0x00, 0x00, 0x40]);
        let mut src = ReadCursor::new(&bytes);
        let decoded = ChannelCreated::decode(&mut src).unwrap();
        assert_eq!(decoded, server);
        decoded.validate_version().unwrap();

        let client = ChannelCreated::client(8);
        let bytes = encode_vec(&client);
        assert_eq!(&bytes[0..4], &[0x03, 0x00, 0x00, 0x40]);
    }

    #[test]
    fn add_virtual_channel_roundtrip() {
        let avc = AddVirtualChannel::new(5);
        let bytes = encode_vec(&avc);
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[0..4], &[0x01, 0x00, 0x00, 0x40]);
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(AddVirtualChannel::decode(&mut src).unwrap(), avc);
    }

    #[test]
    fn add_device_full_roundtrip() {
        let pdu = sample_add_device();
        let bytes = encode_vec(&pdu);
        let mut src = ReadCursor::new(&bytes);
        let decoded = AddDevice::decode(&mut src).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn add_device_no_hwids_no_compatids() {
        let mut pdu = sample_add_device();
        pdu.hardware_ids = None;
        pdu.compatibility_ids = None;
        let bytes = encode_vec(&pdu);
        let mut src = ReadCursor::new(&bytes);
        let decoded = AddDevice::decode(&mut src).unwrap();
        assert_eq!(decoded, pdu);
        assert!(decoded.hardware_ids.is_none());
        assert!(decoded.compatibility_ids.is_none());
    }

    #[test]
    fn add_device_all_zero_container_id_rejected() {
        let mut pdu = sample_add_device();
        pdu.container_id = Utf16String::from_str("{00000000-0000-0000-0000-000000000000}");
        let mut buf = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        assert!(pdu.encode(&mut cur).is_err());
    }

    #[test]
    fn usb_device_capabilities_cbsize_must_be_28() {
        let mut caps = sample_caps();
        caps.cb_size = 32;
        let mut buf = [0u8; 28];
        let mut cur = WriteCursor::new(&mut buf);
        assert!(caps.encode(&mut cur).is_err());
    }

    #[test]
    fn usb_device_capabilities_noack_bounds() {
        let mut caps = sample_caps();
        caps.no_ack_isoch_write_jitter_buffer_size_in_ms = 9;
        assert!(caps.validate().is_err());
        caps.no_ack_isoch_write_jitter_buffer_size_in_ms = 513;
        assert!(caps.validate().is_err());
        caps.no_ack_isoch_write_jitter_buffer_size_in_ms = 10;
        caps.validate().unwrap();
        caps.no_ack_isoch_write_jitter_buffer_size_in_ms = 512;
        caps.validate().unwrap();
        caps.no_ack_isoch_write_jitter_buffer_size_in_ms = 0;
        caps.validate().unwrap();
    }

    #[test]
    fn cancel_request_roundtrip() {
        let pdu = CancelRequest::new(0x100, 1, 0xDEAD_BEEF);
        let bytes = encode_vec(&pdu);
        assert_eq!(bytes.len(), 16);
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(CancelRequest::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn register_request_callback_roundtrips() {
        let with = RegisterRequestCallback::new(0x100, 1, 0x200);
        let bytes = encode_vec(&with);
        assert_eq!(bytes.len(), 20);
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(RegisterRequestCallback::decode(&mut src).unwrap(), with);

        let without = RegisterRequestCallback {
            header: SharedMsgHeader::request(
                0x100,
                Mask::StreamIdProxy,
                2,
                FN_REGISTER_REQUEST_CALLBACK,
            ),
            num_request_completion: 0,
            request_completion: None,
        };
        let bytes = encode_vec(&without);
        assert_eq!(bytes.len(), 16);
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(RegisterRequestCallback::decode(&mut src).unwrap(), without);
    }

    #[test]
    fn io_control_roundtrip() {
        let pdu = IoControl {
            header: SharedMsgHeader::request(0x100, Mask::StreamIdProxy, 1, FN_IO_CONTROL),
            io_control_code: 0x22_0000,
            input_buffer: vec![1, 2, 3, 4],
            output_buffer_size: 16,
            request_id: 7,
        };
        let bytes = encode_vec(&pdu);
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(IoControl::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn query_device_text_rsp_empty() {
        let rsp = QueryDeviceTextRsp {
            header: SharedMsgHeader::response(0x100, 3),
            device_description: None,
            h_result: HRESULT_S_OK,
        };
        let bytes = encode_vec(&rsp);
        assert_eq!(bytes.len(), 16);
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(QueryDeviceTextRsp::decode(&mut src).unwrap(), rsp);
    }

    #[test]
    fn query_device_text_rsp_with_description() {
        let rsp = QueryDeviceTextRsp {
            header: SharedMsgHeader::response(0x100, 3),
            device_description: Some(Utf16String::from_str("Widget")),
            h_result: HRESULT_S_OK,
        };
        let bytes = encode_vec(&rsp);
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(QueryDeviceTextRsp::decode(&mut src).unwrap(), rsp);
    }

    #[test]
    fn retract_device_roundtrip() {
        let pdu = RetractDevice {
            header: SharedMsgHeader::request(0x100, Mask::StreamIdProxy, 4, FN_RETRACT_DEVICE),
            reason: USB_RETRACT_REASON_BLOCKED_BY_POLICY,
        };
        let bytes = encode_vec(&pdu);
        assert_eq!(bytes.len(), 16);
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(RetractDevice::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn io_control_completion_error_rejects_nonzero_output() {
        let pdu = IoControlCompletion {
            header: SharedMsgHeader::request(
                0x200,
                Mask::StreamIdProxy,
                1,
                FN_IOCONTROL_COMPLETION,
            ),
            request_id: 7,
            h_result: HRESULT_E_FAIL,
            information: 0,
            output_buffer_size: 4,
            output_buffer: vec![0; 4],
        };
        assert!(pdu.validate().is_err());
    }

    #[test]
    fn io_control_completion_success_roundtrip() {
        let pdu = IoControlCompletion {
            header: SharedMsgHeader::request(
                0x200,
                Mask::StreamIdProxy,
                1,
                FN_IOCONTROL_COMPLETION,
            ),
            request_id: 7,
            h_result: HRESULT_S_OK,
            information: 4,
            output_buffer_size: 4,
            output_buffer: vec![1, 2, 3, 4],
        };
        let bytes = encode_vec(&pdu);
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(IoControlCompletion::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn urb_completion_no_data_transfer_in_must_have_zero_output() {
        let pdu = UrbCompletionNoData {
            header: SharedMsgHeader::request(
                0x200,
                Mask::StreamIdProxy,
                1,
                FN_URB_COMPLETION_NO_DATA,
            ),
            request_id: 7,
            cb_ts_urb_result: 8,
            ts_urb_result: {
                // TS_URB_RESULT_HEADER: Size=8, Padding=0, UsbdStatus=0.
                let mut v = vec![0u8; 8];
                v[0] = 8;
                v
            },
            h_result: HRESULT_S_OK,
            output_buffer_size: 5,
        };
        assert!(pdu
            .validate_for_source(UrbCompletionSource::TransferIn)
            .is_err());
    }
}
