#![forbid(unsafe_code)]

//! `TS_URB_*` structures. MS-RDPEUSB 2.2.9
//!
//! Each variant is encoded/decoded on its own; the enclosing `cb_ts_urb`
//! field of a `TRANSFER_*_REQUEST` carries the byte length. The
//! `TS_URB_HEADER.Size` field MUST match that length exactly.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use crate::pdu::{MAX_CB_TS_URB, MAX_DEVICE_PIPES, MAX_ISOCH_PACKETS, MAX_SELECT_CONFIG_INTERFACES};

// ── URB_FUNCTION_* values (MSFT-W2KDDK Vol 2 Pt 4 Ch 3 — subset used here) ──
pub const URB_FUNCTION_SELECT_CONFIGURATION: u16 = 0x0000;
pub const URB_FUNCTION_SELECT_INTERFACE: u16 = 0x0001;
pub const URB_FUNCTION_SYNC_RESET_PIPE: u16 = 0x001E;
pub const URB_FUNCTION_GET_CURRENT_FRAME_NUMBER: u16 = 0x0014;
pub const URB_FUNCTION_CONTROL_TRANSFER: u16 = 0x0008;
pub const URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER: u16 = 0x0009;
pub const URB_FUNCTION_ISOCH_TRANSFER: u16 = 0x000A;
pub const URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE: u16 = 0x000B;
pub const URB_FUNCTION_SET_FEATURE_TO_DEVICE: u16 = 0x000D;
pub const URB_FUNCTION_GET_STATUS_FROM_DEVICE: u16 = 0x0013;
pub const URB_FUNCTION_VENDOR_DEVICE: u16 = 0x0017;
pub const URB_FUNCTION_GET_CONFIGURATION: u16 = 0x0026;
pub const URB_FUNCTION_GET_INTERFACE: u16 = 0x0028;
pub const URB_FUNCTION_OS_FEATURE_DESCRIPTOR_REQUEST: u16 = 0x0033;
pub const URB_FUNCTION_CONTROL_TRANSFER_EX: u16 = 0x0032;

// =============================================================================
// TS_URB_HEADER (MS-RDPEUSB 2.2.9.1.1) — 8 bytes
// =============================================================================

/// `TS_URB_HEADER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsUrbHeader {
    /// Total byte length of the containing TS_URB (header + body).
    pub size: u16,
    /// `URB_FUNCTION_*`.
    pub function: u16,
    /// 31-bit request identifier.
    pub request_id: u32,
    /// `NoAck` (A) flag — high bit of the LE u32 at offset 4.
    pub no_ack: bool,
}

impl TsUrbHeader {
    pub const WIRE_SIZE: usize = 8;

    pub fn new(size: u16, function: u16, request_id: u32) -> Self {
        Self {
            size,
            function,
            request_id,
            no_ack: false,
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.request_id > 0x7FFF_FFFF {
            return Err("RequestId > 31 bits");
        }
        if self.no_ack && self.function != URB_FUNCTION_ISOCH_TRANSFER {
            return Err("NoAck only allowed on URB_FUNCTION_ISOCH_TRANSFER");
        }
        Ok(())
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        self.validate()
            .map_err(|_| EncodeError::invalid_value("TsUrbHeader", "validation"))?;
        dst.write_u16_le(self.size, "TS_URB_HEADER::Size")?;
        dst.write_u16_le(self.function, "TS_URB_HEADER::Function")?;
        let word =
            (self.request_id & 0x7FFF_FFFF) | (if self.no_ack { 1u32 << 31 } else { 0 });
        dst.write_u32_le(word, "TS_URB_HEADER::RequestId+NoAck")?;
        Ok(())
    }

    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let size = src.read_u16_le("TS_URB_HEADER::Size")?;
        let function = src.read_u16_le("TS_URB_HEADER::Function")?;
        let word = src.read_u32_le("TS_URB_HEADER::RequestId+NoAck")?;
        let request_id = word & 0x7FFF_FFFF;
        let no_ack = (word & (1 << 31)) != 0;
        let hdr = Self {
            size,
            function,
            request_id,
            no_ack,
        };
        // We allow decoding NoAck=1 on non-isoch functions (lenient — we
        // validate on encode). On decode, only range-check `size`.
        if (hdr.size as u32) > MAX_CB_TS_URB {
            return Err(DecodeError::invalid_value("TsUrbHeader", "Size > cap"));
        }
        Ok(hdr)
    }
}

// =============================================================================
// TS_URB_RESULT_HEADER (MS-RDPEUSB 2.2.10.1.1) — 8 bytes
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsUrbResultHeader {
    pub size: u16,
    pub padding: u16,
    pub usbd_status: u32,
}

impl TsUrbResultHeader {
    pub const WIRE_SIZE: usize = 8;

    pub fn new(size: u16, usbd_status: u32) -> Self {
        Self {
            size,
            padding: 0,
            usbd_status,
        }
    }
}

impl Encode for TsUrbResultHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.size, "TS_URB_RESULT_HEADER::Size")?;
        dst.write_u16_le(self.padding, "TS_URB_RESULT_HEADER::Padding")?;
        dst.write_u32_le(self.usbd_status, "TS_URB_RESULT_HEADER::UsbdStatus")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbResultHeader"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for TsUrbResultHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let size = src.read_u16_le("TS_URB_RESULT_HEADER::Size")?;
        let padding = src.read_u16_le("TS_URB_RESULT_HEADER::Padding")?;
        let usbd_status = src.read_u32_le("TS_URB_RESULT_HEADER::UsbdStatus")?;
        Ok(Self {
            size,
            padding,
            usbd_status,
        })
    }
}

// =============================================================================
// TS_USBD_PIPE_INFORMATION (MS-RDPEUSB 2.2.9.1.3) — 12 bytes
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsUsbdPipeInformation {
    pub maximum_packet_size: u16,
    pub padding: u16,
    pub maximum_transfer_size: u32,
    pub pipe_flags: u32,
}

impl TsUsbdPipeInformation {
    pub const WIRE_SIZE: usize = 12;
}

impl Encode for TsUsbdPipeInformation {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.maximum_packet_size, "TsUsbdPipeInformation::MaxPkt")?;
        dst.write_u16_le(self.padding, "TsUsbdPipeInformation::Padding")?;
        dst.write_u32_le(self.maximum_transfer_size, "TsUsbdPipeInformation::MaxXfer")?;
        dst.write_u32_le(self.pipe_flags, "TsUsbdPipeInformation::PipeFlags")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUsbdPipeInformation"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for TsUsbdPipeInformation {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let maximum_packet_size = src.read_u16_le("TsUsbdPipeInformation::MaxPkt")?;
        let padding = src.read_u16_le("TsUsbdPipeInformation::Padding")?;
        let maximum_transfer_size = src.read_u32_le("TsUsbdPipeInformation::MaxXfer")?;
        let pipe_flags = src.read_u32_le("TsUsbdPipeInformation::PipeFlags")?;
        Ok(Self {
            maximum_packet_size,
            padding,
            maximum_transfer_size,
            pipe_flags,
        })
    }
}

// =============================================================================
// TS_USBD_INTERFACE_INFORMATION (MS-RDPEUSB 2.2.9.1.2)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsUsbdInterfaceInformation {
    pub length: u16,
    pub number_of_pipes_expected: u16,
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub padding: u16,
    pub number_of_pipes: u32,
    pub pipes: Vec<TsUsbdPipeInformation>,
}

impl TsUsbdInterfaceInformation {
    /// Compute the encoded length from the `pipes` vector. Saturates at
    /// `u16::MAX` — callers MUST pair this with the `MAX_DEVICE_PIPES` cap
    /// check, otherwise silently truncated lengths could bypass the
    /// encode-side `length != computed_length()` guard.
    #[must_use]
    pub fn computed_length(&self) -> u16 {
        let bytes = 12usize.saturating_add(
            self.pipes
                .len()
                .saturating_mul(TsUsbdPipeInformation::WIRE_SIZE),
        );
        u16::try_from(bytes).unwrap_or(u16::MAX)
    }
}

impl Encode for TsUsbdInterfaceInformation {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.pipes.len() as u32 != self.number_of_pipes {
            return Err(EncodeError::invalid_value(
                "TsUsbdInterfaceInformation",
                "NumberOfPipes",
            ));
        }
        if self.number_of_pipes > MAX_DEVICE_PIPES {
            return Err(EncodeError::invalid_value(
                "TsUsbdInterfaceInformation",
                "NumberOfPipes > cap",
            ));
        }
        if self.length != self.computed_length() {
            return Err(EncodeError::invalid_value(
                "TsUsbdInterfaceInformation",
                "Length",
            ));
        }
        dst.write_u16_le(self.length, "TsUsbdInterfaceInformation::Length")?;
        dst.write_u16_le(
            self.number_of_pipes_expected,
            "TsUsbdInterfaceInformation::NumberOfPipesExpected",
        )?;
        dst.write_u8(
            self.interface_number,
            "TsUsbdInterfaceInformation::InterfaceNumber",
        )?;
        dst.write_u8(
            self.alternate_setting,
            "TsUsbdInterfaceInformation::AlternateSetting",
        )?;
        dst.write_u16_le(self.padding, "TsUsbdInterfaceInformation::Padding")?;
        dst.write_u32_le(
            self.number_of_pipes,
            "TsUsbdInterfaceInformation::NumberOfPipes",
        )?;
        for p in &self.pipes {
            p.encode(dst)?;
        }
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUsbdInterfaceInformation"
    }
    fn size(&self) -> usize {
        12 + self.pipes.len() * TsUsbdPipeInformation::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for TsUsbdInterfaceInformation {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let length = src.read_u16_le("TsUsbdInterfaceInformation::Length")?;
        let number_of_pipes_expected =
            src.read_u16_le("TsUsbdInterfaceInformation::NumberOfPipesExpected")?;
        let interface_number = src.read_u8("TsUsbdInterfaceInformation::InterfaceNumber")?;
        let alternate_setting = src.read_u8("TsUsbdInterfaceInformation::AlternateSetting")?;
        let padding = src.read_u16_le("TsUsbdInterfaceInformation::Padding")?;
        let number_of_pipes = src.read_u32_le("TsUsbdInterfaceInformation::NumberOfPipes")?;
        if number_of_pipes > MAX_DEVICE_PIPES {
            return Err(DecodeError::invalid_value(
                "TsUsbdInterfaceInformation",
                "NumberOfPipes > cap",
            ));
        }
        // Overflow-safe width computation. MAX_DEVICE_PIPES (64) keeps this
        // well under u16::MAX today; the `checked_*` path guards against a
        // future cap raise silently truncating and bypassing the length
        // consistency check below.
        let expected_bytes = (number_of_pipes as usize)
            .checked_mul(TsUsbdPipeInformation::WIRE_SIZE)
            .and_then(|b| b.checked_add(12))
            .ok_or_else(|| {
                DecodeError::invalid_value("TsUsbdInterfaceInformation", "Length overflow")
            })?;
        let expected_length = u16::try_from(expected_bytes).map_err(|_| {
            DecodeError::invalid_value("TsUsbdInterfaceInformation", "Length > u16")
        })?;
        if length != expected_length {
            return Err(DecodeError::invalid_value(
                "TsUsbdInterfaceInformation",
                "Length",
            ));
        }
        let mut pipes = Vec::with_capacity(number_of_pipes as usize);
        for _ in 0..number_of_pipes {
            pipes.push(TsUsbdPipeInformation::decode(src)?);
        }
        Ok(Self {
            length,
            number_of_pipes_expected,
            interface_number,
            alternate_setting,
            padding,
            number_of_pipes,
            pipes,
        })
    }
}

// =============================================================================
// TS_URB_SELECT_CONFIGURATION (MS-RDPEUSB 2.2.9.2)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsUrbSelectConfiguration {
    pub header: TsUrbHeader,
    pub configuration_descriptor_is_valid: u8,
    pub padding: [u8; 3],
    pub num_interfaces: u32,
    pub interfaces: Vec<TsUsbdInterfaceInformation>,
    /// Optional USB_CONFIGURATION_DESCRIPTOR trailer (raw bytes).
    pub configuration_descriptor: Vec<u8>,
}

impl TsUrbSelectConfiguration {
    pub fn size_bytes(&self) -> usize {
        let mut n = TsUrbHeader::WIRE_SIZE + 1 + 3 + 4;
        for i in &self.interfaces {
            n += i.size();
        }
        n += self.configuration_descriptor.len();
        n
    }
}

impl Encode for TsUrbSelectConfiguration {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.interfaces.len() as u32 != self.num_interfaces {
            return Err(EncodeError::invalid_value(
                "TsUrbSelectConfiguration",
                "NumInterfaces",
            ));
        }
        if self.num_interfaces > MAX_SELECT_CONFIG_INTERFACES {
            return Err(EncodeError::invalid_value(
                "TsUrbSelectConfiguration",
                "NumInterfaces > cap",
            ));
        }
        if self.header.size as usize != self.size_bytes() {
            return Err(EncodeError::invalid_value(
                "TsUrbSelectConfiguration",
                "TS_URB_HEADER.Size mismatch",
            ));
        }
        if self.header.function != URB_FUNCTION_SELECT_CONFIGURATION {
            return Err(EncodeError::invalid_value(
                "TsUrbSelectConfiguration",
                "Function",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u8(
            self.configuration_descriptor_is_valid,
            "TsUrbSelectConfiguration::CfgDescValid",
        )?;
        dst.write_slice(&self.padding, "TsUrbSelectConfiguration::Padding")?;
        dst.write_u32_le(self.num_interfaces, "TsUrbSelectConfiguration::NumInterfaces")?;
        for i in &self.interfaces {
            i.encode(dst)?;
        }
        dst.write_slice(
            &self.configuration_descriptor,
            "TsUrbSelectConfiguration::CfgDesc",
        )?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbSelectConfiguration"
    }
    fn size(&self) -> usize {
        self.size_bytes()
    }
}

impl TsUrbSelectConfiguration {
    pub fn decode_body(header: TsUrbHeader, src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let configuration_descriptor_is_valid =
            src.read_u8("TsUrbSelectConfiguration::CfgDescValid")?;
        let pad = src.read_slice(3, "TsUrbSelectConfiguration::Padding")?;
        let padding = [pad[0], pad[1], pad[2]];
        let num_interfaces = src.read_u32_le("TsUrbSelectConfiguration::NumInterfaces")?;
        if num_interfaces > MAX_SELECT_CONFIG_INTERFACES {
            return Err(DecodeError::invalid_value(
                "TsUrbSelectConfiguration",
                "NumInterfaces > cap",
            ));
        }
        let mut interfaces = Vec::with_capacity(num_interfaces as usize);
        // After the NumInterfaces field we are 16 bytes in. The remaining
        // bytes before the trailing configuration descriptor are exactly the
        // interface blocks; we read exactly `num_interfaces` of them.
        for _ in 0..num_interfaces {
            interfaces.push(TsUsbdInterfaceInformation::decode(src)?);
        }
        // Remaining bytes are the optional configuration descriptor. Compute
        // by subtracting from header.size.
        let consumed = TsUrbHeader::WIRE_SIZE
            + 1
            + 3
            + 4
            + interfaces.iter().map(|i| i.size()).sum::<usize>();
        let total = header.size as usize;
        if total < consumed {
            return Err(DecodeError::invalid_value(
                "TsUrbSelectConfiguration",
                "TS_URB_HEADER.Size",
            ));
        }
        let tail = total - consumed;
        let configuration_descriptor = src
            .read_slice(tail, "TsUrbSelectConfiguration::CfgDesc")?
            .to_vec();
        Ok(Self {
            header,
            configuration_descriptor_is_valid,
            padding,
            num_interfaces,
            interfaces,
            configuration_descriptor,
        })
    }
}

// =============================================================================
// TS_URB_SELECT_INTERFACE (MS-RDPEUSB 2.2.9.3)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsUrbSelectInterface {
    pub header: TsUrbHeader,
    pub configuration_handle: u32,
    pub interface_info: TsUsbdInterfaceInformation,
}

impl TsUrbSelectInterface {
    pub fn size_bytes(&self) -> usize {
        TsUrbHeader::WIRE_SIZE + 4 + self.interface_info.size()
    }
}

impl Encode for TsUrbSelectInterface {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.function != URB_FUNCTION_SELECT_INTERFACE {
            return Err(EncodeError::invalid_value(
                "TsUrbSelectInterface",
                "Function",
            ));
        }
        if self.header.size as usize != self.size_bytes() {
            return Err(EncodeError::invalid_value(
                "TsUrbSelectInterface",
                "TS_URB_HEADER.Size mismatch",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(
            self.configuration_handle,
            "TsUrbSelectInterface::ConfigurationHandle",
        )?;
        self.interface_info.encode(dst)?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbSelectInterface"
    }
    fn size(&self) -> usize {
        self.size_bytes()
    }
}

impl TsUrbSelectInterface {
    pub fn decode_body(header: TsUrbHeader, src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let configuration_handle =
            src.read_u32_le("TsUrbSelectInterface::ConfigurationHandle")?;
        let interface_info = TsUsbdInterfaceInformation::decode(src)?;
        Ok(Self {
            header,
            configuration_handle,
            interface_info,
        })
    }
}

// =============================================================================
// Simple fixed-size variants
// =============================================================================

macro_rules! fixed_urb {
    (
        $name:ident, $size:expr, $function:expr;
        $( $field:ident : $ty:ty ),* $(,)?
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name {
            pub header: TsUrbHeader,
            $( pub $field: $ty ),*
        }
        impl $name {
            pub const WIRE_SIZE: usize = $size;
        }
        impl $name {
            pub fn decode_body(header: TsUrbHeader, src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
                $( let $field = <$ty as ReadField>::read(src, stringify!($name), stringify!($field))?; )*
                Ok(Self { header, $( $field ),* })
            }
        }
    };
}

// Helper trait for reading primitive fields in the macro.
trait ReadField: Sized {
    fn read(src: &mut ReadCursor<'_>, ctx: &'static str, field: &'static str) -> DecodeResult<Self>;
}
impl ReadField for u8 {
    fn read(src: &mut ReadCursor<'_>, _c: &'static str, _f: &'static str) -> DecodeResult<Self> {
        src.read_u8("ts_urb::u8")
    }
}
impl ReadField for u16 {
    fn read(src: &mut ReadCursor<'_>, _c: &'static str, _f: &'static str) -> DecodeResult<Self> {
        src.read_u16_le("ts_urb::u16")
    }
}
impl ReadField for u32 {
    fn read(src: &mut ReadCursor<'_>, _c: &'static str, _f: &'static str) -> DecodeResult<Self> {
        src.read_u32_le("ts_urb::u32")
    }
}
impl ReadField for [u8; 8] {
    fn read(src: &mut ReadCursor<'_>, _c: &'static str, _f: &'static str) -> DecodeResult<Self> {
        let s = src.read_slice(8, "ts_urb::[u8;8]")?;
        Ok([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    }
}

// ── TS_URB_PIPE_REQUEST (2.2.9.4) 12 B ──
fixed_urb!(TsUrbPipeRequest, 12, URB_FUNCTION_SYNC_RESET_PIPE;
    pipe_handle: u32,
);

impl Encode for TsUrbPipeRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.size as usize != Self::WIRE_SIZE {
            return Err(EncodeError::invalid_value("TsUrbPipeRequest", "Size"));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.pipe_handle, "TsUrbPipeRequest::PipeHandle")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbPipeRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// ── TS_URB_GET_CURRENT_FRAME_NUMBER (2.2.9.5) 8 B ──
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsUrbGetCurrentFrameNumber {
    pub header: TsUrbHeader,
}

impl TsUrbGetCurrentFrameNumber {
    pub const WIRE_SIZE: usize = 8;
    pub fn decode_body(header: TsUrbHeader, _src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        Ok(Self { header })
    }
}

impl Encode for TsUrbGetCurrentFrameNumber {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.size as usize != Self::WIRE_SIZE {
            return Err(EncodeError::invalid_value(
                "TsUrbGetCurrentFrameNumber",
                "Size",
            ));
        }
        self.header.encode(dst)
    }
    fn name(&self) -> &'static str {
        "TsUrbGetCurrentFrameNumber"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// ── TS_URB_CONTROL_TRANSFER (2.2.9.6) 24 B ──
fixed_urb!(TsUrbControlTransfer, 24, URB_FUNCTION_CONTROL_TRANSFER;
    pipe_handle: u32,
    transfer_flags: u32,
    setup_packet: [u8; 8],
);

impl Encode for TsUrbControlTransfer {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.size as usize != Self::WIRE_SIZE {
            return Err(EncodeError::invalid_value("TsUrbControlTransfer", "Size"));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.pipe_handle, "TsUrbControlTransfer::PipeHandle")?;
        dst.write_u32_le(self.transfer_flags, "TsUrbControlTransfer::TransferFlags")?;
        dst.write_slice(&self.setup_packet, "TsUrbControlTransfer::SetupPacket")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbControlTransfer"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// ── TS_URB_BULK_OR_INTERRUPT_TRANSFER (2.2.9.7) 16 B ──
fixed_urb!(TsUrbBulkOrInterruptTransfer, 16, URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER;
    pipe_handle: u32,
    transfer_flags: u32,
);

impl Encode for TsUrbBulkOrInterruptTransfer {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.size as usize != Self::WIRE_SIZE {
            return Err(EncodeError::invalid_value(
                "TsUrbBulkOrInterruptTransfer",
                "Size",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.pipe_handle, "TsUrbBulkOrInterruptTransfer::PipeHandle")?;
        dst.write_u32_le(
            self.transfer_flags,
            "TsUrbBulkOrInterruptTransfer::TransferFlags",
        )?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbBulkOrInterruptTransfer"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// ── USBD_ISO_PACKET_DESCRIPTOR (12 B) ──
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbdIsoPacketDescriptor {
    pub offset: u32,
    pub length: u32,
    pub status: u32,
}

impl UsbdIsoPacketDescriptor {
    pub const WIRE_SIZE: usize = 12;
}

impl Encode for UsbdIsoPacketDescriptor {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.offset, "IsoPkt::Offset")?;
        dst.write_u32_le(self.length, "IsoPkt::Length")?;
        dst.write_u32_le(self.status, "IsoPkt::Status")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "UsbdIsoPacketDescriptor"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}
impl<'de> Decode<'de> for UsbdIsoPacketDescriptor {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let offset = src.read_u32_le("IsoPkt::Offset")?;
        let length = src.read_u32_le("IsoPkt::Length")?;
        let status = src.read_u32_le("IsoPkt::Status")?;
        Ok(Self {
            offset,
            length,
            status,
        })
    }
}

// ── TS_URB_ISOCH_TRANSFER (2.2.9.8) 28 B + packets ──
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsUrbIsochTransfer {
    pub header: TsUrbHeader,
    pub pipe_handle: u32,
    pub transfer_flags: u32,
    pub start_frame: u32,
    pub number_of_packets: u32,
    pub error_count: u32,
    pub iso_packets: Vec<UsbdIsoPacketDescriptor>,
}

impl TsUrbIsochTransfer {
    pub const FIXED_SIZE: usize = 28;
    pub fn size_bytes(&self) -> usize {
        Self::FIXED_SIZE + self.iso_packets.len() * UsbdIsoPacketDescriptor::WIRE_SIZE
    }
}

impl Encode for TsUrbIsochTransfer {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.number_of_packets > MAX_ISOCH_PACKETS {
            return Err(EncodeError::invalid_value(
                "TsUrbIsochTransfer",
                "NumberOfPackets > cap",
            ));
        }
        if self.iso_packets.len() as u32 != self.number_of_packets {
            return Err(EncodeError::invalid_value(
                "TsUrbIsochTransfer",
                "NumberOfPackets mismatch",
            ));
        }
        if self.header.function != URB_FUNCTION_ISOCH_TRANSFER {
            return Err(EncodeError::invalid_value("TsUrbIsochTransfer", "Function"));
        }
        if self.header.size as usize != self.size_bytes() {
            return Err(EncodeError::invalid_value("TsUrbIsochTransfer", "Size"));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.pipe_handle, "TsUrbIsochTransfer::PipeHandle")?;
        dst.write_u32_le(self.transfer_flags, "TsUrbIsochTransfer::TransferFlags")?;
        dst.write_u32_le(self.start_frame, "TsUrbIsochTransfer::StartFrame")?;
        dst.write_u32_le(
            self.number_of_packets,
            "TsUrbIsochTransfer::NumberOfPackets",
        )?;
        dst.write_u32_le(self.error_count, "TsUrbIsochTransfer::ErrorCount")?;
        for p in &self.iso_packets {
            p.encode(dst)?;
        }
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbIsochTransfer"
    }
    fn size(&self) -> usize {
        self.size_bytes()
    }
}

impl TsUrbIsochTransfer {
    pub fn decode_body(header: TsUrbHeader, src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let pipe_handle = src.read_u32_le("TsUrbIsochTransfer::PipeHandle")?;
        let transfer_flags = src.read_u32_le("TsUrbIsochTransfer::TransferFlags")?;
        let start_frame = src.read_u32_le("TsUrbIsochTransfer::StartFrame")?;
        let number_of_packets = src.read_u32_le("TsUrbIsochTransfer::NumberOfPackets")?;
        if number_of_packets > MAX_ISOCH_PACKETS {
            return Err(DecodeError::invalid_value(
                "TsUrbIsochTransfer",
                "NumberOfPackets > cap",
            ));
        }
        let error_count = src.read_u32_le("TsUrbIsochTransfer::ErrorCount")?;
        let mut iso_packets = Vec::with_capacity(number_of_packets as usize);
        for _ in 0..number_of_packets {
            iso_packets.push(UsbdIsoPacketDescriptor::decode(src)?);
        }
        Ok(Self {
            header,
            pipe_handle,
            transfer_flags,
            start_frame,
            number_of_packets,
            error_count,
            iso_packets,
        })
    }
}

// ── TS_URB_CONTROL_DESCRIPTOR_REQUEST (2.2.9.9) 12 B ──
fixed_urb!(TsUrbControlDescriptorRequest, 12, URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE;
    index: u8,
    descriptor_type: u8,
    language_id: u16,
);

impl Encode for TsUrbControlDescriptorRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.size as usize != Self::WIRE_SIZE {
            return Err(EncodeError::invalid_value(
                "TsUrbControlDescriptorRequest",
                "Size",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u8(self.index, "TsUrbControlDescriptorRequest::Index")?;
        dst.write_u8(
            self.descriptor_type,
            "TsUrbControlDescriptorRequest::DescriptorType",
        )?;
        dst.write_u16_le(self.language_id, "TsUrbControlDescriptorRequest::LanguageId")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbControlDescriptorRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// ── TS_URB_CONTROL_FEATURE_REQUEST (2.2.9.10) 12 B ──
fixed_urb!(TsUrbControlFeatureRequest, 12, URB_FUNCTION_SET_FEATURE_TO_DEVICE;
    feature_selector: u16,
    index: u16,
);

impl Encode for TsUrbControlFeatureRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.size as usize != Self::WIRE_SIZE {
            return Err(EncodeError::invalid_value(
                "TsUrbControlFeatureRequest",
                "Size",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u16_le(
            self.feature_selector,
            "TsUrbControlFeatureRequest::FeatureSelector",
        )?;
        dst.write_u16_le(self.index, "TsUrbControlFeatureRequest::Index")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbControlFeatureRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// ── TS_URB_CONTROL_GET_STATUS_REQUEST (2.2.9.11) 12 B ──
fixed_urb!(TsUrbControlGetStatusRequest, 12, URB_FUNCTION_GET_STATUS_FROM_DEVICE;
    index: u16,
    padding: u16,
);

impl Encode for TsUrbControlGetStatusRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.size as usize != Self::WIRE_SIZE {
            return Err(EncodeError::invalid_value(
                "TsUrbControlGetStatusRequest",
                "Size",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u16_le(self.index, "TsUrbControlGetStatusRequest::Index")?;
        dst.write_u16_le(self.padding, "TsUrbControlGetStatusRequest::Padding")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbControlGetStatusRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// ── TS_URB_CONTROL_VENDOR_OR_CLASS_REQUEST (2.2.9.12) 20 B ──
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsUrbControlVendorOrClassRequest {
    pub header: TsUrbHeader,
    pub transfer_flags: u32,
    pub request_type_reserved_bits: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub padding: u16,
}

impl TsUrbControlVendorOrClassRequest {
    pub const WIRE_SIZE: usize = 20;
    pub fn decode_body(header: TsUrbHeader, src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let transfer_flags = src.read_u32_le("TsUrbControlVendorOrClassRequest::TransferFlags")?;
        let request_type_reserved_bits =
            src.read_u8("TsUrbControlVendorOrClassRequest::RequestTypeReservedBits")?;
        let request = src.read_u8("TsUrbControlVendorOrClassRequest::Request")?;
        let value = src.read_u16_le("TsUrbControlVendorOrClassRequest::Value")?;
        let index = src.read_u16_le("TsUrbControlVendorOrClassRequest::Index")?;
        let padding = src.read_u16_le("TsUrbControlVendorOrClassRequest::Padding")?;
        Ok(Self {
            header,
            transfer_flags,
            request_type_reserved_bits,
            request,
            value,
            index,
            padding,
        })
    }
}

impl Encode for TsUrbControlVendorOrClassRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.size as usize != Self::WIRE_SIZE {
            return Err(EncodeError::invalid_value(
                "TsUrbControlVendorOrClassRequest",
                "Size",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(
            self.transfer_flags,
            "TsUrbControlVendorOrClassRequest::TransferFlags",
        )?;
        dst.write_u8(
            self.request_type_reserved_bits,
            "TsUrbControlVendorOrClassRequest::RequestTypeReservedBits",
        )?;
        dst.write_u8(self.request, "TsUrbControlVendorOrClassRequest::Request")?;
        dst.write_u16_le(self.value, "TsUrbControlVendorOrClassRequest::Value")?;
        dst.write_u16_le(self.index, "TsUrbControlVendorOrClassRequest::Index")?;
        dst.write_u16_le(self.padding, "TsUrbControlVendorOrClassRequest::Padding")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbControlVendorOrClassRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// ── TS_URB_CONTROL_GET_CONFIGURATION_REQUEST (2.2.9.13) 8 B ──
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsUrbControlGetConfigurationRequest {
    pub header: TsUrbHeader,
}

impl TsUrbControlGetConfigurationRequest {
    pub const WIRE_SIZE: usize = 8;
    pub fn decode_body(header: TsUrbHeader, _src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        Ok(Self { header })
    }
}

impl Encode for TsUrbControlGetConfigurationRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.size as usize != Self::WIRE_SIZE {
            return Err(EncodeError::invalid_value(
                "TsUrbControlGetConfigurationRequest",
                "Size",
            ));
        }
        self.header.encode(dst)
    }
    fn name(&self) -> &'static str {
        "TsUrbControlGetConfigurationRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// ── TS_URB_CONTROL_GET_INTERFACE_REQUEST (2.2.9.14) 12 B ──
fixed_urb!(TsUrbControlGetInterfaceRequest, 12, URB_FUNCTION_GET_INTERFACE;
    interface: u16,
    padding: u16,
);

impl Encode for TsUrbControlGetInterfaceRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.size as usize != Self::WIRE_SIZE {
            return Err(EncodeError::invalid_value(
                "TsUrbControlGetInterfaceRequest",
                "Size",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u16_le(self.interface, "TsUrbControlGetInterfaceRequest::Interface")?;
        dst.write_u16_le(self.padding, "TsUrbControlGetInterfaceRequest::Padding")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbControlGetInterfaceRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// ── TS_URB_OS_FEATURE_DESCRIPTOR_REQUEST (2.2.9.15) 16 B ──
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsUrbOsFeatureDescriptorRequest {
    pub header: TsUrbHeader,
    /// Low 5 bits — high 3 bits are reserved / padding.
    pub recipient: u8,
    pub interface_number: u8,
    pub ms_page_index: u8,
    pub pad1: u8,
    pub ms_feature_descriptor_index: u16,
    pub padding2: [u8; 2],
}

impl TsUrbOsFeatureDescriptorRequest {
    pub const WIRE_SIZE: usize = 16;

    pub fn decode_body(header: TsUrbHeader, src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let byte = src.read_u8("TsUrbOsFeatureDescriptorRequest::Recipient/Padding")?;
        // Low 5 bits are Recipient, high 3 bits are Padding and MUST be ignored on decode.
        let recipient = byte & 0x1F;
        let interface_number = src.read_u8("TsUrbOsFeatureDescriptorRequest::InterfaceNumber")?;
        let ms_page_index = src.read_u8("TsUrbOsFeatureDescriptorRequest::MS_PageIndex")?;
        let pad1 = src.read_u8("TsUrbOsFeatureDescriptorRequest::Pad1")?;
        let ms_feature_descriptor_index = src.read_u16_le(
            "TsUrbOsFeatureDescriptorRequest::MS_FeatureDescriptorIndex",
        )?;
        let p = src.read_slice(2, "TsUrbOsFeatureDescriptorRequest::Padding2")?;
        Ok(Self {
            header,
            recipient,
            interface_number,
            ms_page_index,
            pad1,
            ms_feature_descriptor_index,
            padding2: [p[0], p[1]],
        })
    }
}

impl Encode for TsUrbOsFeatureDescriptorRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.size as usize != Self::WIRE_SIZE {
            return Err(EncodeError::invalid_value(
                "TsUrbOsFeatureDescriptorRequest",
                "Size",
            ));
        }
        if self.recipient > 0x1F {
            return Err(EncodeError::invalid_value(
                "TsUrbOsFeatureDescriptorRequest",
                "Recipient (>5 bits)",
            ));
        }
        self.header.encode(dst)?;
        // High 3 bits MUST be zero per 2.2.9.15 on encode.
        dst.write_u8(
            self.recipient & 0x1F,
            "TsUrbOsFeatureDescriptorRequest::Recipient/Padding",
        )?;
        dst.write_u8(
            self.interface_number,
            "TsUrbOsFeatureDescriptorRequest::InterfaceNumber",
        )?;
        dst.write_u8(
            self.ms_page_index,
            "TsUrbOsFeatureDescriptorRequest::MS_PageIndex",
        )?;
        dst.write_u8(self.pad1, "TsUrbOsFeatureDescriptorRequest::Pad1")?;
        dst.write_u16_le(
            self.ms_feature_descriptor_index,
            "TsUrbOsFeatureDescriptorRequest::MS_FeatureDescriptorIndex",
        )?;
        dst.write_slice(
            &self.padding2,
            "TsUrbOsFeatureDescriptorRequest::Padding2",
        )?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbOsFeatureDescriptorRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// ── TS_URB_CONTROL_TRANSFER_EX (2.2.9.16) 28 B ──
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsUrbControlTransferEx {
    pub header: TsUrbHeader,
    pub pipe_handle: u32,
    pub transfer_flags: u32,
    pub timeout: u32,
    pub setup_packet: [u8; 8],
}

impl TsUrbControlTransferEx {
    pub const WIRE_SIZE: usize = 28;
    pub fn decode_body(header: TsUrbHeader, src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let pipe_handle = src.read_u32_le("TsUrbControlTransferEx::PipeHandle")?;
        let transfer_flags = src.read_u32_le("TsUrbControlTransferEx::TransferFlags")?;
        let timeout = src.read_u32_le("TsUrbControlTransferEx::Timeout")?;
        let sp = src.read_slice(8, "TsUrbControlTransferEx::SetupPacket")?;
        Ok(Self {
            header,
            pipe_handle,
            transfer_flags,
            timeout,
            setup_packet: [sp[0], sp[1], sp[2], sp[3], sp[4], sp[5], sp[6], sp[7]],
        })
    }
}

impl Encode for TsUrbControlTransferEx {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.header.size as usize != Self::WIRE_SIZE {
            return Err(EncodeError::invalid_value(
                "TsUrbControlTransferEx",
                "Size",
            ));
        }
        self.header.encode(dst)?;
        dst.write_u32_le(self.pipe_handle, "TsUrbControlTransferEx::PipeHandle")?;
        dst.write_u32_le(
            self.transfer_flags,
            "TsUrbControlTransferEx::TransferFlags",
        )?;
        dst.write_u32_le(self.timeout, "TsUrbControlTransferEx::Timeout")?;
        dst.write_slice(&self.setup_packet, "TsUrbControlTransferEx::SetupPacket")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "TsUrbControlTransferEx"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// =============================================================================
// TsUrb dispatch enum
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TsUrb {
    SelectConfiguration(TsUrbSelectConfiguration),
    SelectInterface(TsUrbSelectInterface),
    PipeRequest(TsUrbPipeRequest),
    GetCurrentFrameNumber(TsUrbGetCurrentFrameNumber),
    ControlTransfer(TsUrbControlTransfer),
    BulkOrInterruptTransfer(TsUrbBulkOrInterruptTransfer),
    IsochTransfer(TsUrbIsochTransfer),
    ControlDescriptorRequest(TsUrbControlDescriptorRequest),
    ControlFeatureRequest(TsUrbControlFeatureRequest),
    ControlGetStatusRequest(TsUrbControlGetStatusRequest),
    ControlVendorOrClassRequest(TsUrbControlVendorOrClassRequest),
    ControlGetConfigurationRequest(TsUrbControlGetConfigurationRequest),
    ControlGetInterfaceRequest(TsUrbControlGetInterfaceRequest),
    OsFeatureDescriptorRequest(TsUrbOsFeatureDescriptorRequest),
    ControlTransferEx(TsUrbControlTransferEx),
    /// Variants outside the implemented set are stored raw (header + body).
    Other { header: TsUrbHeader, raw_body: Vec<u8> },
}

impl TsUrb {
    pub fn header(&self) -> &TsUrbHeader {
        match self {
            Self::SelectConfiguration(v) => &v.header,
            Self::SelectInterface(v) => &v.header,
            Self::PipeRequest(v) => &v.header,
            Self::GetCurrentFrameNumber(v) => &v.header,
            Self::ControlTransfer(v) => &v.header,
            Self::BulkOrInterruptTransfer(v) => &v.header,
            Self::IsochTransfer(v) => &v.header,
            Self::ControlDescriptorRequest(v) => &v.header,
            Self::ControlFeatureRequest(v) => &v.header,
            Self::ControlGetStatusRequest(v) => &v.header,
            Self::ControlVendorOrClassRequest(v) => &v.header,
            Self::ControlGetConfigurationRequest(v) => &v.header,
            Self::ControlGetInterfaceRequest(v) => &v.header,
            Self::OsFeatureDescriptorRequest(v) => &v.header,
            Self::ControlTransferEx(v) => &v.header,
            Self::Other { header, .. } => header,
        }
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        match self {
            Self::SelectConfiguration(v) => v.encode(dst),
            Self::SelectInterface(v) => v.encode(dst),
            Self::PipeRequest(v) => v.encode(dst),
            Self::GetCurrentFrameNumber(v) => v.encode(dst),
            Self::ControlTransfer(v) => v.encode(dst),
            Self::BulkOrInterruptTransfer(v) => v.encode(dst),
            Self::IsochTransfer(v) => v.encode(dst),
            Self::ControlDescriptorRequest(v) => v.encode(dst),
            Self::ControlFeatureRequest(v) => v.encode(dst),
            Self::ControlGetStatusRequest(v) => v.encode(dst),
            Self::ControlVendorOrClassRequest(v) => v.encode(dst),
            Self::ControlGetConfigurationRequest(v) => v.encode(dst),
            Self::ControlGetInterfaceRequest(v) => v.encode(dst),
            Self::OsFeatureDescriptorRequest(v) => v.encode(dst),
            Self::ControlTransferEx(v) => v.encode(dst),
            Self::Other { header, raw_body } => {
                header.encode(dst)?;
                dst.write_slice(raw_body, "TsUrb::Other::body")?;
                Ok(())
            }
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::SelectConfiguration(v) => v.size(),
            Self::SelectInterface(v) => v.size(),
            Self::PipeRequest(v) => v.size(),
            Self::GetCurrentFrameNumber(v) => v.size(),
            Self::ControlTransfer(v) => v.size(),
            Self::BulkOrInterruptTransfer(v) => v.size(),
            Self::IsochTransfer(v) => v.size(),
            Self::ControlDescriptorRequest(v) => v.size(),
            Self::ControlFeatureRequest(v) => v.size(),
            Self::ControlGetStatusRequest(v) => v.size(),
            Self::ControlVendorOrClassRequest(v) => v.size(),
            Self::ControlGetConfigurationRequest(v) => v.size(),
            Self::ControlGetInterfaceRequest(v) => v.size(),
            Self::OsFeatureDescriptorRequest(v) => v.size(),
            Self::ControlTransferEx(v) => v.size(),
            Self::Other { header: _, raw_body } => TsUrbHeader::WIRE_SIZE + raw_body.len(),
        }
    }

    /// Decode from a raw TS_URB byte slice (length == `header.size`).
    pub fn decode(bytes: &[u8]) -> DecodeResult<Self> {
        if bytes.len() < TsUrbHeader::WIRE_SIZE {
            return Err(DecodeError::invalid_value("TsUrb", "too short"));
        }
        let mut src = ReadCursor::new(bytes);
        let header = TsUrbHeader::decode(&mut src)?;
        if header.size as usize != bytes.len() {
            return Err(DecodeError::invalid_value(
                "TsUrb",
                "TS_URB_HEADER.Size != slice length",
            ));
        }
        match header.function {
            URB_FUNCTION_SELECT_CONFIGURATION => Ok(Self::SelectConfiguration(
                TsUrbSelectConfiguration::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_SELECT_INTERFACE => Ok(Self::SelectInterface(
                TsUrbSelectInterface::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_SYNC_RESET_PIPE => Ok(Self::PipeRequest(
                TsUrbPipeRequest::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_GET_CURRENT_FRAME_NUMBER => Ok(Self::GetCurrentFrameNumber(
                TsUrbGetCurrentFrameNumber::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_CONTROL_TRANSFER => Ok(Self::ControlTransfer(
                TsUrbControlTransfer::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER => Ok(Self::BulkOrInterruptTransfer(
                TsUrbBulkOrInterruptTransfer::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_ISOCH_TRANSFER => Ok(Self::IsochTransfer(
                TsUrbIsochTransfer::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE => Ok(Self::ControlDescriptorRequest(
                TsUrbControlDescriptorRequest::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_SET_FEATURE_TO_DEVICE => Ok(Self::ControlFeatureRequest(
                TsUrbControlFeatureRequest::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_GET_STATUS_FROM_DEVICE => Ok(Self::ControlGetStatusRequest(
                TsUrbControlGetStatusRequest::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_VENDOR_DEVICE => Ok(Self::ControlVendorOrClassRequest(
                TsUrbControlVendorOrClassRequest::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_GET_CONFIGURATION => Ok(Self::ControlGetConfigurationRequest(
                TsUrbControlGetConfigurationRequest::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_GET_INTERFACE => Ok(Self::ControlGetInterfaceRequest(
                TsUrbControlGetInterfaceRequest::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_OS_FEATURE_DESCRIPTOR_REQUEST => Ok(Self::OsFeatureDescriptorRequest(
                TsUrbOsFeatureDescriptorRequest::decode_body(header, &mut src)?,
            )),
            URB_FUNCTION_CONTROL_TRANSFER_EX => Ok(Self::ControlTransferEx(
                TsUrbControlTransferEx::decode_body(header, &mut src)?,
            )),
            _ => {
                let body = src
                    .read_slice(header.size as usize - TsUrbHeader::WIRE_SIZE, "TsUrb::Other")?
                    .to_vec();
                Ok(Self::Other {
                    header,
                    raw_body: body,
                })
            }
        }
    }

    pub fn encode_to_vec(&self) -> EncodeResult<Vec<u8>> {
        let mut buf = alloc::vec![0u8; self.size()];
        let mut cur = WriteCursor::new(&mut buf);
        self.encode(&mut cur)?;
        Ok(buf)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn roundtrip_urb(urb: TsUrb) {
        let bytes = urb.encode_to_vec().expect("encode");
        assert_eq!(bytes.len(), urb.size());
        let decoded = TsUrb::decode(&bytes).expect("decode");
        assert_eq!(decoded, urb);
    }

    #[test]
    fn pipe_request_roundtrip() {
        let urb = TsUrb::PipeRequest(TsUrbPipeRequest {
            header: TsUrbHeader::new(
                TsUrbPipeRequest::WIRE_SIZE as u16,
                URB_FUNCTION_SYNC_RESET_PIPE,
                1,
            ),
            pipe_handle: 0x1234_5678,
        });
        roundtrip_urb(urb);
    }

    #[test]
    fn bulk_or_interrupt_transfer_roundtrip() {
        let urb = TsUrb::BulkOrInterruptTransfer(TsUrbBulkOrInterruptTransfer {
            header: TsUrbHeader::new(
                TsUrbBulkOrInterruptTransfer::WIRE_SIZE as u16,
                URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER,
                42,
            ),
            pipe_handle: 0xDEAD_BEEF,
            transfer_flags: 0x0000_0003,
        });
        roundtrip_urb(urb);
    }

    #[test]
    fn control_transfer_roundtrip() {
        let urb = TsUrb::ControlTransfer(TsUrbControlTransfer {
            header: TsUrbHeader::new(
                TsUrbControlTransfer::WIRE_SIZE as u16,
                URB_FUNCTION_CONTROL_TRANSFER,
                7,
            ),
            pipe_handle: 1,
            transfer_flags: 2,
            setup_packet: [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00],
        });
        roundtrip_urb(urb);
    }

    #[test]
    fn isoch_transfer_zero_packets() {
        let urb = TsUrb::IsochTransfer(TsUrbIsochTransfer {
            header: TsUrbHeader::new(
                TsUrbIsochTransfer::FIXED_SIZE as u16,
                URB_FUNCTION_ISOCH_TRANSFER,
                1,
            ),
            pipe_handle: 1,
            transfer_flags: 0,
            start_frame: 0,
            number_of_packets: 0,
            error_count: 0,
            iso_packets: Vec::new(),
        });
        roundtrip_urb(urb);
    }

    #[test]
    fn isoch_transfer_too_many_packets_rejected_on_encode() {
        let header = TsUrbHeader::new(
            (TsUrbIsochTransfer::FIXED_SIZE + 2000 * 12) as u16,
            URB_FUNCTION_ISOCH_TRANSFER,
            1,
        );
        let urb = TsUrbIsochTransfer {
            header,
            pipe_handle: 0,
            transfer_flags: 0,
            start_frame: 0,
            number_of_packets: 2000,
            error_count: 0,
            iso_packets: vec![UsbdIsoPacketDescriptor { offset: 0, length: 0, status: 0 }; 2000],
        };
        let mut buf = vec![0u8; urb.size()];
        let mut cur = WriteCursor::new(&mut buf);
        assert!(urb.encode(&mut cur).is_err());
    }

    #[test]
    fn no_ack_on_non_isoch_rejected_on_encode() {
        let mut hdr = TsUrbHeader::new(
            TsUrbPipeRequest::WIRE_SIZE as u16,
            URB_FUNCTION_SYNC_RESET_PIPE,
            1,
        );
        hdr.no_ack = true;
        let mut buf = [0u8; 8];
        let mut cur = WriteCursor::new(&mut buf);
        assert!(hdr.encode(&mut cur).is_err());
    }

    #[test]
    fn get_current_frame_number_roundtrip() {
        let urb = TsUrb::GetCurrentFrameNumber(TsUrbGetCurrentFrameNumber {
            header: TsUrbHeader::new(
                TsUrbGetCurrentFrameNumber::WIRE_SIZE as u16,
                URB_FUNCTION_GET_CURRENT_FRAME_NUMBER,
                1,
            ),
        });
        roundtrip_urb(urb);
    }

    #[test]
    fn os_feature_descriptor_roundtrip() {
        let urb = TsUrb::OsFeatureDescriptorRequest(TsUrbOsFeatureDescriptorRequest {
            header: TsUrbHeader::new(
                TsUrbOsFeatureDescriptorRequest::WIRE_SIZE as u16,
                URB_FUNCTION_OS_FEATURE_DESCRIPTOR_REQUEST,
                1,
            ),
            recipient: 0x15,
            interface_number: 1,
            ms_page_index: 2,
            pad1: 0,
            ms_feature_descriptor_index: 4,
            padding2: [0, 0],
        });
        roundtrip_urb(urb);
    }

    #[test]
    fn select_configuration_minimal_roundtrip() {
        let header = TsUrbHeader::new(16, URB_FUNCTION_SELECT_CONFIGURATION, 1);
        let urb = TsUrb::SelectConfiguration(TsUrbSelectConfiguration {
            header,
            configuration_descriptor_is_valid: 0,
            padding: [0, 0, 0],
            num_interfaces: 0,
            interfaces: Vec::new(),
            configuration_descriptor: Vec::new(),
        });
        roundtrip_urb(urb);
    }
}
