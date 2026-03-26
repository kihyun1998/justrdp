#![forbid(unsafe_code)]

//! RDP Capability Sets -- MS-RDPBCGR 2.2.7
//!
//! Defines all 30 capability set types exchanged during the Demand Active /
//! Confirm Active handshake, plus the wrapping PDU types.

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

// ── Capability header ──

pub const CAPABILITY_HEADER_SIZE: usize = 4; // type(2) + length(2)

/// Capability set type identifiers (MS-RDPBCGR 2.2.7.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CapabilitySetType {
    General = 0x0001,
    Bitmap = 0x0002,
    Order = 0x0003,
    BitmapCache = 0x0004,
    Control = 0x0005,
    Activation = 0x0007,
    Pointer = 0x0008,
    Share = 0x0009,
    ColorCache = 0x000A,
    Sound = 0x000C,
    Input = 0x000D,
    Font = 0x000E,
    Brush = 0x000F,
    GlyphCache = 0x0010,
    OffscreenCache = 0x0011,
    BitmapCacheHostSupport = 0x0012,
    BitmapCacheRev2 = 0x0013,
    VirtualChannel = 0x0014,
    DrawNineGridCache = 0x0015,
    DrawGdiPlus = 0x0016,
    Rail = 0x0017,
    Window = 0x0018,
    DesktopComposition = 0x0019,
    MultifragmentUpdate = 0x001A,
    LargePointer = 0x001B,
    SurfaceCommands = 0x001C,
    BitmapCodecs = 0x001D,
    FrameAcknowledge = 0x001E,
}

impl CapabilitySetType {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x0001 => Some(Self::General),
            0x0002 => Some(Self::Bitmap),
            0x0003 => Some(Self::Order),
            0x0004 => Some(Self::BitmapCache),
            0x0005 => Some(Self::Control),
            0x0007 => Some(Self::Activation),
            0x0008 => Some(Self::Pointer),
            0x0009 => Some(Self::Share),
            0x000A => Some(Self::ColorCache),
            0x000C => Some(Self::Sound),
            0x000D => Some(Self::Input),
            0x000E => Some(Self::Font),
            0x000F => Some(Self::Brush),
            0x0010 => Some(Self::GlyphCache),
            0x0011 => Some(Self::OffscreenCache),
            0x0012 => Some(Self::BitmapCacheHostSupport),
            0x0013 => Some(Self::BitmapCacheRev2),
            0x0014 => Some(Self::VirtualChannel),
            0x0015 => Some(Self::DrawNineGridCache),
            0x0016 => Some(Self::DrawGdiPlus),
            0x0017 => Some(Self::Rail),
            0x0018 => Some(Self::Window),
            0x0019 => Some(Self::DesktopComposition),
            0x001A => Some(Self::MultifragmentUpdate),
            0x001B => Some(Self::LargePointer),
            0x001C => Some(Self::SurfaceCommands),
            0x001D => Some(Self::BitmapCodecs),
            0x001E => Some(Self::FrameAcknowledge),
            _ => None,
        }
    }
}

// ── Individual capability set structs ──

/// General Capability Set (MS-RDPBCGR 2.2.7.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralCapability {
    pub os_major_type: u16,
    pub os_minor_type: u16,
    pub protocol_version: u16,
    pub pad2: u16,
    pub general_compression_types: u16,
    pub extra_flags: u16,
    pub update_capability_flag: u16,
    pub remote_unshare_flag: u16,
    pub general_compression_level: u16,
    pub refresh_rect_support: u8,
    pub suppress_output_support: u8,
}

const GENERAL_BODY_SIZE: usize = 20;

impl Encode for GeneralCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.os_major_type, "General::osMajorType")?;
        dst.write_u16_le(self.os_minor_type, "General::osMinorType")?;
        dst.write_u16_le(self.protocol_version, "General::protocolVersion")?;
        dst.write_u16_le(self.pad2, "General::pad2")?;
        dst.write_u16_le(self.general_compression_types, "General::generalCompressionTypes")?;
        dst.write_u16_le(self.extra_flags, "General::extraFlags")?;
        dst.write_u16_le(self.update_capability_flag, "General::updateCapabilityFlag")?;
        dst.write_u16_le(self.remote_unshare_flag, "General::remoteUnshareFlag")?;
        dst.write_u16_le(self.general_compression_level, "General::generalCompressionLevel")?;
        dst.write_u8(self.refresh_rect_support, "General::refreshRectSupport")?;
        dst.write_u8(self.suppress_output_support, "General::suppressOutputSupport")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "GeneralCapability" }
    fn size(&self) -> usize { GENERAL_BODY_SIZE }
}

impl<'de> Decode<'de> for GeneralCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            os_major_type: src.read_u16_le("General::osMajorType")?,
            os_minor_type: src.read_u16_le("General::osMinorType")?,
            protocol_version: src.read_u16_le("General::protocolVersion")?,
            pad2: src.read_u16_le("General::pad2")?,
            general_compression_types: src.read_u16_le("General::generalCompressionTypes")?,
            extra_flags: src.read_u16_le("General::extraFlags")?,
            update_capability_flag: src.read_u16_le("General::updateCapabilityFlag")?,
            remote_unshare_flag: src.read_u16_le("General::remoteUnshareFlag")?,
            general_compression_level: src.read_u16_le("General::generalCompressionLevel")?,
            refresh_rect_support: src.read_u8("General::refreshRectSupport")?,
            suppress_output_support: src.read_u8("General::suppressOutputSupport")?,
        })
    }
}

/// Bitmap Capability Set (MS-RDPBCGR 2.2.7.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapCapability {
    pub preferred_bits_per_pixel: u16,
    pub receive1_bit_per_pixel: u16,
    pub receive4_bits_per_pixel: u16,
    pub receive8_bits_per_pixel: u16,
    pub desktop_width: u16,
    pub desktop_height: u16,
    pub pad2a: u16,
    pub desktop_resize_flag: u16,
    pub bitmap_compression_flag: u16,
    pub high_color_flags: u8,
    pub drawing_flags: u8,
    pub multiple_rectangle_support: u16,
    pub pad2b: u16,
}

const BITMAP_BODY_SIZE: usize = 24;

impl Encode for BitmapCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.preferred_bits_per_pixel, "Bitmap::preferredBitsPerPixel")?;
        dst.write_u16_le(self.receive1_bit_per_pixel, "Bitmap::receive1BitPerPixel")?;
        dst.write_u16_le(self.receive4_bits_per_pixel, "Bitmap::receive4BitsPerPixel")?;
        dst.write_u16_le(self.receive8_bits_per_pixel, "Bitmap::receive8BitsPerPixel")?;
        dst.write_u16_le(self.desktop_width, "Bitmap::desktopWidth")?;
        dst.write_u16_le(self.desktop_height, "Bitmap::desktopHeight")?;
        dst.write_u16_le(self.pad2a, "Bitmap::pad2a")?;
        dst.write_u16_le(self.desktop_resize_flag, "Bitmap::desktopResizeFlag")?;
        dst.write_u16_le(self.bitmap_compression_flag, "Bitmap::bitmapCompressionFlag")?;
        dst.write_u8(self.high_color_flags, "Bitmap::highColorFlags")?;
        dst.write_u8(self.drawing_flags, "Bitmap::drawingFlags")?;
        dst.write_u16_le(self.multiple_rectangle_support, "Bitmap::multipleRectangleSupport")?;
        dst.write_u16_le(self.pad2b, "Bitmap::pad2b")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "BitmapCapability" }
    fn size(&self) -> usize { BITMAP_BODY_SIZE }
}

impl<'de> Decode<'de> for BitmapCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            preferred_bits_per_pixel: src.read_u16_le("Bitmap::preferredBitsPerPixel")?,
            receive1_bit_per_pixel: src.read_u16_le("Bitmap::receive1BitPerPixel")?,
            receive4_bits_per_pixel: src.read_u16_le("Bitmap::receive4BitsPerPixel")?,
            receive8_bits_per_pixel: src.read_u16_le("Bitmap::receive8BitsPerPixel")?,
            desktop_width: src.read_u16_le("Bitmap::desktopWidth")?,
            desktop_height: src.read_u16_le("Bitmap::desktopHeight")?,
            pad2a: src.read_u16_le("Bitmap::pad2a")?,
            desktop_resize_flag: src.read_u16_le("Bitmap::desktopResizeFlag")?,
            bitmap_compression_flag: src.read_u16_le("Bitmap::bitmapCompressionFlag")?,
            high_color_flags: src.read_u8("Bitmap::highColorFlags")?,
            drawing_flags: src.read_u8("Bitmap::drawingFlags")?,
            multiple_rectangle_support: src.read_u16_le("Bitmap::multipleRectangleSupport")?,
            pad2b: src.read_u16_le("Bitmap::pad2b")?,
        })
    }
}

/// Order Capability Set (MS-RDPBCGR 2.2.7.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderCapability {
    pub terminal_descriptor: [u8; 16],
    pub pad4: u32,
    pub desktop_save_x_granularity: u16,
    pub desktop_save_y_granularity: u16,
    pub pad2a: u16,
    pub maximum_order_level: u16,
    pub number_fonts: u16,
    pub order_flags: u16,
    pub order_support: [u8; 32],
    pub text_flags: u16,
    pub order_support_ex_flags: u16,
    pub pad4b: u32,
    pub desktop_save_size: u32,
    pub pad2b: u16,
    pub pad2c: u16,
    pub text_ansi_code_page: u16,
    pub pad2d: u16,
}

const ORDER_BODY_SIZE: usize = 84;

impl Encode for OrderCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_slice(&self.terminal_descriptor, "Order::terminalDescriptor")?;
        dst.write_u32_le(self.pad4, "Order::pad4")?;
        dst.write_u16_le(self.desktop_save_x_granularity, "Order::desktopSaveXGranularity")?;
        dst.write_u16_le(self.desktop_save_y_granularity, "Order::desktopSaveYGranularity")?;
        dst.write_u16_le(self.pad2a, "Order::pad2a")?;
        dst.write_u16_le(self.maximum_order_level, "Order::maximumOrderLevel")?;
        dst.write_u16_le(self.number_fonts, "Order::numberFonts")?;
        dst.write_u16_le(self.order_flags, "Order::orderFlags")?;
        dst.write_slice(&self.order_support, "Order::orderSupport")?;
        dst.write_u16_le(self.text_flags, "Order::textFlags")?;
        dst.write_u16_le(self.order_support_ex_flags, "Order::orderSupportExFlags")?;
        dst.write_u32_le(self.pad4b, "Order::pad4b")?;
        dst.write_u32_le(self.desktop_save_size, "Order::desktopSaveSize")?;
        dst.write_u16_le(self.pad2b, "Order::pad2b")?;
        dst.write_u16_le(self.pad2c, "Order::pad2c")?;
        dst.write_u16_le(self.text_ansi_code_page, "Order::textANSICodePage")?;
        dst.write_u16_le(self.pad2d, "Order::pad2d")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "OrderCapability" }
    fn size(&self) -> usize { ORDER_BODY_SIZE }
}

impl<'de> Decode<'de> for OrderCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let mut terminal_descriptor = [0u8; 16];
        terminal_descriptor.copy_from_slice(src.read_slice(16, "Order::terminalDescriptor")?);
        let pad4 = src.read_u32_le("Order::pad4")?;
        let desktop_save_x_granularity = src.read_u16_le("Order::desktopSaveXGranularity")?;
        let desktop_save_y_granularity = src.read_u16_le("Order::desktopSaveYGranularity")?;
        let pad2a = src.read_u16_le("Order::pad2a")?;
        let maximum_order_level = src.read_u16_le("Order::maximumOrderLevel")?;
        let number_fonts = src.read_u16_le("Order::numberFonts")?;
        let order_flags = src.read_u16_le("Order::orderFlags")?;
        let mut order_support = [0u8; 32];
        order_support.copy_from_slice(src.read_slice(32, "Order::orderSupport")?);
        let text_flags = src.read_u16_le("Order::textFlags")?;
        let order_support_ex_flags = src.read_u16_le("Order::orderSupportExFlags")?;
        let pad4b = src.read_u32_le("Order::pad4b")?;
        let desktop_save_size = src.read_u32_le("Order::desktopSaveSize")?;
        let pad2b = src.read_u16_le("Order::pad2b")?;
        let pad2c = src.read_u16_le("Order::pad2c")?;
        let text_ansi_code_page = src.read_u16_le("Order::textANSICodePage")?;
        let pad2d = src.read_u16_le("Order::pad2d")?;
        Ok(Self {
            terminal_descriptor, pad4, desktop_save_x_granularity, desktop_save_y_granularity,
            pad2a, maximum_order_level, number_fonts, order_flags, order_support,
            text_flags, order_support_ex_flags, pad4b, desktop_save_size,
            pad2b, pad2c, text_ansi_code_page, pad2d,
        })
    }
}

/// Bitmap Cache Capability Set (Revision 1) (MS-RDPBCGR 2.2.7.1.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapCacheCapability {
    pub pad1: u32,
    pub pad2: u32,
    pub pad3: u32,
    pub pad4: u32,
    pub pad5: u32,
    pub pad6: u32,
    pub cache0_entries: u16,
    pub cache0_max_cell_size: u16,
    pub cache1_entries: u16,
    pub cache1_max_cell_size: u16,
    pub cache2_entries: u16,
    pub cache2_max_cell_size: u16,
}

const BITMAP_CACHE_BODY_SIZE: usize = 36;

impl Encode for BitmapCacheCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.pad1, "BitmapCache::pad1")?;
        dst.write_u32_le(self.pad2, "BitmapCache::pad2")?;
        dst.write_u32_le(self.pad3, "BitmapCache::pad3")?;
        dst.write_u32_le(self.pad4, "BitmapCache::pad4")?;
        dst.write_u32_le(self.pad5, "BitmapCache::pad5")?;
        dst.write_u32_le(self.pad6, "BitmapCache::pad6")?;
        dst.write_u16_le(self.cache0_entries, "BitmapCache::cache0Entries")?;
        dst.write_u16_le(self.cache0_max_cell_size, "BitmapCache::cache0MaxCellSize")?;
        dst.write_u16_le(self.cache1_entries, "BitmapCache::cache1Entries")?;
        dst.write_u16_le(self.cache1_max_cell_size, "BitmapCache::cache1MaxCellSize")?;
        dst.write_u16_le(self.cache2_entries, "BitmapCache::cache2Entries")?;
        dst.write_u16_le(self.cache2_max_cell_size, "BitmapCache::cache2MaxCellSize")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "BitmapCacheCapability" }
    fn size(&self) -> usize { BITMAP_CACHE_BODY_SIZE }
}

impl<'de> Decode<'de> for BitmapCacheCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            pad1: src.read_u32_le("BitmapCache::pad1")?,
            pad2: src.read_u32_le("BitmapCache::pad2")?,
            pad3: src.read_u32_le("BitmapCache::pad3")?,
            pad4: src.read_u32_le("BitmapCache::pad4")?,
            pad5: src.read_u32_le("BitmapCache::pad5")?,
            pad6: src.read_u32_le("BitmapCache::pad6")?,
            cache0_entries: src.read_u16_le("BitmapCache::cache0Entries")?,
            cache0_max_cell_size: src.read_u16_le("BitmapCache::cache0MaxCellSize")?,
            cache1_entries: src.read_u16_le("BitmapCache::cache1Entries")?,
            cache1_max_cell_size: src.read_u16_le("BitmapCache::cache1MaxCellSize")?,
            cache2_entries: src.read_u16_le("BitmapCache::cache2Entries")?,
            cache2_max_cell_size: src.read_u16_le("BitmapCache::cache2MaxCellSize")?,
        })
    }
}

/// Bitmap Cache Capability Set (Revision 2) (MS-RDPBCGR 2.2.7.1.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapCacheRev2Capability {
    pub cache_flags: u16,
    pub pad2: u8,
    pub num_cell_caches: u8,
    pub bitmap_cache0_cell_info: u32,
    pub bitmap_cache1_cell_info: u32,
    pub bitmap_cache2_cell_info: u32,
    pub bitmap_cache3_cell_info: u32,
    pub bitmap_cache4_cell_info: u32,
    pub pad3: [u8; 12],
}

const BITMAP_CACHE_REV2_BODY_SIZE: usize = 36;

impl Encode for BitmapCacheRev2Capability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.cache_flags, "BitmapCacheRev2::cacheFlags")?;
        dst.write_u8(self.pad2, "BitmapCacheRev2::pad2")?;
        dst.write_u8(self.num_cell_caches, "BitmapCacheRev2::numCellCaches")?;
        dst.write_u32_le(self.bitmap_cache0_cell_info, "BitmapCacheRev2::cache0")?;
        dst.write_u32_le(self.bitmap_cache1_cell_info, "BitmapCacheRev2::cache1")?;
        dst.write_u32_le(self.bitmap_cache2_cell_info, "BitmapCacheRev2::cache2")?;
        dst.write_u32_le(self.bitmap_cache3_cell_info, "BitmapCacheRev2::cache3")?;
        dst.write_u32_le(self.bitmap_cache4_cell_info, "BitmapCacheRev2::cache4")?;
        dst.write_slice(&self.pad3, "BitmapCacheRev2::pad3")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "BitmapCacheRev2Capability" }
    fn size(&self) -> usize { BITMAP_CACHE_REV2_BODY_SIZE }
}

impl<'de> Decode<'de> for BitmapCacheRev2Capability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cache_flags = src.read_u16_le("BitmapCacheRev2::cacheFlags")?;
        let pad2 = src.read_u8("BitmapCacheRev2::pad2")?;
        let num_cell_caches = src.read_u8("BitmapCacheRev2::numCellCaches")?;
        let bitmap_cache0_cell_info = src.read_u32_le("BitmapCacheRev2::cache0")?;
        let bitmap_cache1_cell_info = src.read_u32_le("BitmapCacheRev2::cache1")?;
        let bitmap_cache2_cell_info = src.read_u32_le("BitmapCacheRev2::cache2")?;
        let bitmap_cache3_cell_info = src.read_u32_le("BitmapCacheRev2::cache3")?;
        let bitmap_cache4_cell_info = src.read_u32_le("BitmapCacheRev2::cache4")?;
        let mut pad3 = [0u8; 12];
        pad3.copy_from_slice(src.read_slice(12, "BitmapCacheRev2::pad3")?);
        Ok(Self {
            cache_flags, pad2, num_cell_caches,
            bitmap_cache0_cell_info, bitmap_cache1_cell_info, bitmap_cache2_cell_info,
            bitmap_cache3_cell_info, bitmap_cache4_cell_info, pad3,
        })
    }
}

/// Control Capability Set (MS-RDPBCGR 2.2.7.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlCapability {
    pub control_flags: u16,
    pub remote_detach_flag: u16,
    pub control_interest: u16,
    pub detach_interest: u16,
}

const CONTROL_BODY_SIZE: usize = 8;

impl Encode for ControlCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.control_flags, "Control::controlFlags")?;
        dst.write_u16_le(self.remote_detach_flag, "Control::remoteDetachFlag")?;
        dst.write_u16_le(self.control_interest, "Control::controlInterest")?;
        dst.write_u16_le(self.detach_interest, "Control::detachInterest")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "ControlCapability" }
    fn size(&self) -> usize { CONTROL_BODY_SIZE }
}

impl<'de> Decode<'de> for ControlCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            control_flags: src.read_u16_le("Control::controlFlags")?,
            remote_detach_flag: src.read_u16_le("Control::remoteDetachFlag")?,
            control_interest: src.read_u16_le("Control::controlInterest")?,
            detach_interest: src.read_u16_le("Control::detachInterest")?,
        })
    }
}

/// Activation Capability Set (MS-RDPBCGR 2.2.7.2.1 -- Window Activation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationCapability {
    pub help_key_flag: u16,
    pub help_key_index_flag: u16,
    pub help_extended_key_flag: u16,
    pub window_manager_key_flag: u16,
}

const ACTIVATION_BODY_SIZE: usize = 8;

impl Encode for ActivationCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.help_key_flag, "Activation::helpKeyFlag")?;
        dst.write_u16_le(self.help_key_index_flag, "Activation::helpKeyIndexFlag")?;
        dst.write_u16_le(self.help_extended_key_flag, "Activation::helpExtendedKeyFlag")?;
        dst.write_u16_le(self.window_manager_key_flag, "Activation::windowManagerKeyFlag")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "ActivationCapability" }
    fn size(&self) -> usize { ACTIVATION_BODY_SIZE }
}

impl<'de> Decode<'de> for ActivationCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            help_key_flag: src.read_u16_le("Activation::helpKeyFlag")?,
            help_key_index_flag: src.read_u16_le("Activation::helpKeyIndexFlag")?,
            help_extended_key_flag: src.read_u16_le("Activation::helpExtendedKeyFlag")?,
            window_manager_key_flag: src.read_u16_le("Activation::windowManagerKeyFlag")?,
        })
    }
}

/// Pointer Capability Set (MS-RDPBCGR 2.2.7.1.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerCapability {
    pub color_pointer_flag: u16,
    pub color_pointer_cache_size: u16,
    pub pointer_cache_size: u16,
}

const POINTER_BODY_SIZE: usize = 6;

impl Encode for PointerCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.color_pointer_flag, "Pointer::colorPointerFlag")?;
        dst.write_u16_le(self.color_pointer_cache_size, "Pointer::colorPointerCacheSize")?;
        dst.write_u16_le(self.pointer_cache_size, "Pointer::pointerCacheSize")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "PointerCapability" }
    fn size(&self) -> usize { POINTER_BODY_SIZE }
}

impl<'de> Decode<'de> for PointerCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            color_pointer_flag: src.read_u16_le("Pointer::colorPointerFlag")?,
            color_pointer_cache_size: src.read_u16_le("Pointer::colorPointerCacheSize")?,
            pointer_cache_size: src.read_u16_le("Pointer::pointerCacheSize")?,
        })
    }
}

/// Share Capability Set (MS-RDPBCGR 2.2.7.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareCapability {
    pub node_id: u16,
    pub pad2: u16,
}

const SHARE_BODY_SIZE: usize = 4;

impl Encode for ShareCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.node_id, "Share::nodeId")?;
        dst.write_u16_le(self.pad2, "Share::pad2")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "ShareCapability" }
    fn size(&self) -> usize { SHARE_BODY_SIZE }
}

impl<'de> Decode<'de> for ShareCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            node_id: src.read_u16_le("Share::nodeId")?,
            pad2: src.read_u16_le("Share::pad2")?,
        })
    }
}

/// Color Cache Capability Set (MS-RDPBCGR 2.2.7.1.6 -- Color Table Cache).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColorCacheCapability {
    pub color_table_cache_size: u16,
    pub pad2: u16,
}

const COLOR_CACHE_BODY_SIZE: usize = 4;

impl Encode for ColorCacheCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.color_table_cache_size, "ColorCache::colorTableCacheSize")?;
        dst.write_u16_le(self.pad2, "ColorCache::pad2")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "ColorCacheCapability" }
    fn size(&self) -> usize { COLOR_CACHE_BODY_SIZE }
}

impl<'de> Decode<'de> for ColorCacheCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            color_table_cache_size: src.read_u16_le("ColorCache::colorTableCacheSize")?,
            pad2: src.read_u16_le("ColorCache::pad2")?,
        })
    }
}

/// Sound Capability Set (MS-RDPBCGR 2.2.7.1.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoundCapability {
    pub sound_flags: u16,
    pub pad2: u16,
}

const SOUND_BODY_SIZE: usize = 4;

impl Encode for SoundCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.sound_flags, "Sound::soundFlags")?;
        dst.write_u16_le(self.pad2, "Sound::pad2")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "SoundCapability" }
    fn size(&self) -> usize { SOUND_BODY_SIZE }
}

impl<'de> Decode<'de> for SoundCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            sound_flags: src.read_u16_le("Sound::soundFlags")?,
            pad2: src.read_u16_le("Sound::pad2")?,
        })
    }
}

/// Input Capability Set (MS-RDPBCGR 2.2.7.1.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputCapability {
    pub input_flags: u16,
    pub pad2: u16,
    pub keyboard_layout: u32,
    pub keyboard_type: u32,
    pub keyboard_sub_type: u32,
    pub keyboard_function_key: u32,
    pub ime_file_name: [u8; 64],
}

const INPUT_BODY_SIZE: usize = 84;

impl Encode for InputCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.input_flags, "Input::inputFlags")?;
        dst.write_u16_le(self.pad2, "Input::pad2")?;
        dst.write_u32_le(self.keyboard_layout, "Input::keyboardLayout")?;
        dst.write_u32_le(self.keyboard_type, "Input::keyboardType")?;
        dst.write_u32_le(self.keyboard_sub_type, "Input::keyboardSubType")?;
        dst.write_u32_le(self.keyboard_function_key, "Input::keyboardFunctionKey")?;
        dst.write_slice(&self.ime_file_name, "Input::imeFileName")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "InputCapability" }
    fn size(&self) -> usize { INPUT_BODY_SIZE }
}

impl<'de> Decode<'de> for InputCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let input_flags = src.read_u16_le("Input::inputFlags")?;
        let pad2 = src.read_u16_le("Input::pad2")?;
        let keyboard_layout = src.read_u32_le("Input::keyboardLayout")?;
        let keyboard_type = src.read_u32_le("Input::keyboardType")?;
        let keyboard_sub_type = src.read_u32_le("Input::keyboardSubType")?;
        let keyboard_function_key = src.read_u32_le("Input::keyboardFunctionKey")?;
        let mut ime_file_name = [0u8; 64];
        ime_file_name.copy_from_slice(src.read_slice(64, "Input::imeFileName")?);
        Ok(Self { input_flags, pad2, keyboard_layout, keyboard_type, keyboard_sub_type, keyboard_function_key, ime_file_name })
    }
}

/// Font Capability Set (MS-RDPBCGR 2.2.7.2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FontCapability {
    pub font_support_flags: u16,
    pub pad2: u16,
}

const FONT_BODY_SIZE: usize = 4;

impl Encode for FontCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.font_support_flags, "Font::fontSupportFlags")?;
        dst.write_u16_le(self.pad2, "Font::pad2")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "FontCapability" }
    fn size(&self) -> usize { FONT_BODY_SIZE }
}

impl<'de> Decode<'de> for FontCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            font_support_flags: src.read_u16_le("Font::fontSupportFlags")?,
            pad2: src.read_u16_le("Font::pad2")?,
        })
    }
}

/// Brush Capability Set (MS-RDPBCGR 2.2.7.1.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrushCapability {
    pub brush_support_level: u32,
}

const BRUSH_BODY_SIZE: usize = 4;

impl Encode for BrushCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.brush_support_level, "Brush::brushSupportLevel")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "BrushCapability" }
    fn size(&self) -> usize { BRUSH_BODY_SIZE }
}

impl<'de> Decode<'de> for BrushCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            brush_support_level: src.read_u32_le("Brush::brushSupportLevel")?,
        })
    }
}

/// Glyph Cache Capability Set (MS-RDPBCGR 2.2.7.1.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlyphCacheCapability {
    /// 10 cache entries, each 4 bytes (cacheEntries(u16) + cacheMaxCellSize(u16)).
    pub glyph_cache: [u8; 40],
    pub frag_cache: u32,
    pub glyph_support_level: u16,
    pub pad2: u16,
}

const GLYPH_CACHE_BODY_SIZE: usize = 48;

impl Encode for GlyphCacheCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_slice(&self.glyph_cache, "GlyphCache::glyphCache")?;
        dst.write_u32_le(self.frag_cache, "GlyphCache::fragCache")?;
        dst.write_u16_le(self.glyph_support_level, "GlyphCache::glyphSupportLevel")?;
        dst.write_u16_le(self.pad2, "GlyphCache::pad2")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "GlyphCacheCapability" }
    fn size(&self) -> usize { GLYPH_CACHE_BODY_SIZE }
}

impl<'de> Decode<'de> for GlyphCacheCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let mut glyph_cache = [0u8; 40];
        glyph_cache.copy_from_slice(src.read_slice(40, "GlyphCache::glyphCache")?);
        let frag_cache = src.read_u32_le("GlyphCache::fragCache")?;
        let glyph_support_level = src.read_u16_le("GlyphCache::glyphSupportLevel")?;
        let pad2 = src.read_u16_le("GlyphCache::pad2")?;
        Ok(Self { glyph_cache, frag_cache, glyph_support_level, pad2 })
    }
}

/// Offscreen Bitmap Cache Capability Set (MS-RDPBCGR 2.2.7.1.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffscreenCacheCapability {
    pub offscreen_support_level: u32,
    pub offscreen_cache_size: u16,
    pub offscreen_cache_entries: u16,
}

const OFFSCREEN_CACHE_BODY_SIZE: usize = 8;

impl Encode for OffscreenCacheCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.offscreen_support_level, "OffscreenCache::supportLevel")?;
        dst.write_u16_le(self.offscreen_cache_size, "OffscreenCache::cacheSize")?;
        dst.write_u16_le(self.offscreen_cache_entries, "OffscreenCache::cacheEntries")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "OffscreenCacheCapability" }
    fn size(&self) -> usize { OFFSCREEN_CACHE_BODY_SIZE }
}

impl<'de> Decode<'de> for OffscreenCacheCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            offscreen_support_level: src.read_u32_le("OffscreenCache::supportLevel")?,
            offscreen_cache_size: src.read_u16_le("OffscreenCache::cacheSize")?,
            offscreen_cache_entries: src.read_u16_le("OffscreenCache::cacheEntries")?,
        })
    }
}

/// Bitmap Cache Host Support Capability Set (MS-RDPBCGR 2.2.7.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapCacheHostSupportCapability {
    pub cache_version: u8,
    pub pad1: u8,
    pub pad2: u16,
}

const BITMAP_CACHE_HOST_SUPPORT_BODY_SIZE: usize = 4;

impl Encode for BitmapCacheHostSupportCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(self.cache_version, "BitmapCacheHostSupport::cacheVersion")?;
        dst.write_u8(self.pad1, "BitmapCacheHostSupport::pad1")?;
        dst.write_u16_le(self.pad2, "BitmapCacheHostSupport::pad2")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "BitmapCacheHostSupportCapability" }
    fn size(&self) -> usize { BITMAP_CACHE_HOST_SUPPORT_BODY_SIZE }
}

impl<'de> Decode<'de> for BitmapCacheHostSupportCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            cache_version: src.read_u8("BitmapCacheHostSupport::cacheVersion")?,
            pad1: src.read_u8("BitmapCacheHostSupport::pad1")?,
            pad2: src.read_u16_le("BitmapCacheHostSupport::pad2")?,
        })
    }
}

/// Virtual Channel Capability Set (MS-RDPBCGR 2.2.7.1.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualChannelCapability {
    pub flags: u32,
    pub vc_chunk_size: Option<u32>,
}

impl Encode for VirtualChannelCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.flags, "VirtualChannel::flags")?;
        if let Some(chunk_size) = self.vc_chunk_size {
            dst.write_u32_le(chunk_size, "VirtualChannel::VCChunkSize")?;
        }
        Ok(())
    }
    fn name(&self) -> &'static str { "VirtualChannelCapability" }
    fn size(&self) -> usize {
        4 + if self.vc_chunk_size.is_some() { 4 } else { 0 }
    }
}

impl VirtualChannelCapability {
    /// Decode with known body length (total capability length minus header).
    pub fn decode_with_len(src: &mut ReadCursor<'_>, body_len: usize) -> DecodeResult<Self> {
        let flags = src.read_u32_le("VirtualChannel::flags")?;
        let vc_chunk_size = if body_len >= 8 {
            Some(src.read_u32_le("VirtualChannel::VCChunkSize")?)
        } else {
            None
        };
        Ok(Self { flags, vc_chunk_size })
    }
}

impl<'de> Decode<'de> for VirtualChannelCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let flags = src.read_u32_le("VirtualChannel::flags")?;
        let vc_chunk_size = if src.remaining() >= 4 {
            Some(src.read_u32_le("VirtualChannel::VCChunkSize")?)
        } else {
            None
        };
        Ok(Self { flags, vc_chunk_size })
    }
}

/// Draw Nine Grid Cache Capability Set (MS-RDPBCGR 2.2.7.2.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrawNineGridCacheCapability {
    pub draw_nine_grid_support_level: u32,
    pub draw_nine_grid_cache_size: u16,
    pub draw_nine_grid_cache_entries: u16,
}

const DRAW_NINE_GRID_CACHE_BODY_SIZE: usize = 8;

impl Encode for DrawNineGridCacheCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.draw_nine_grid_support_level, "DrawNineGrid::supportLevel")?;
        dst.write_u16_le(self.draw_nine_grid_cache_size, "DrawNineGrid::cacheSize")?;
        dst.write_u16_le(self.draw_nine_grid_cache_entries, "DrawNineGrid::cacheEntries")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "DrawNineGridCacheCapability" }
    fn size(&self) -> usize { DRAW_NINE_GRID_CACHE_BODY_SIZE }
}

impl<'de> Decode<'de> for DrawNineGridCacheCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            draw_nine_grid_support_level: src.read_u32_le("DrawNineGrid::supportLevel")?,
            draw_nine_grid_cache_size: src.read_u16_le("DrawNineGrid::cacheSize")?,
            draw_nine_grid_cache_entries: src.read_u16_le("DrawNineGrid::cacheEntries")?,
        })
    }
}

/// Draw GDI+ Cache Capability Set (MS-RDPBCGR 2.2.7.2.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrawGdiPlusCapability {
    pub draw_gdi_plus_support_level: u32,
    pub gdip_version: u32,
    pub draw_gdi_plus_cache_level: u32,
    /// 10 x u16 = 20 bytes.
    pub gdip_cache_entries: [u8; 20],
    /// 8 x u16 = 16 bytes.
    pub gdip_cache_chunk_size: [u8; 16],
    /// 6 x u16 = 12 bytes.
    pub gdip_image_cache_properties: [u8; 12],
}

const DRAW_GDI_PLUS_BODY_SIZE: usize = 60;

impl Encode for DrawGdiPlusCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.draw_gdi_plus_support_level, "DrawGdiPlus::supportLevel")?;
        dst.write_u32_le(self.gdip_version, "DrawGdiPlus::gdipVersion")?;
        dst.write_u32_le(self.draw_gdi_plus_cache_level, "DrawGdiPlus::cacheLevel")?;
        dst.write_slice(&self.gdip_cache_entries, "DrawGdiPlus::cacheEntries")?;
        dst.write_slice(&self.gdip_cache_chunk_size, "DrawGdiPlus::cacheChunkSize")?;
        dst.write_slice(&self.gdip_image_cache_properties, "DrawGdiPlus::imageCacheProperties")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "DrawGdiPlusCapability" }
    fn size(&self) -> usize { DRAW_GDI_PLUS_BODY_SIZE }
}

impl<'de> Decode<'de> for DrawGdiPlusCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let draw_gdi_plus_support_level = src.read_u32_le("DrawGdiPlus::supportLevel")?;
        let gdip_version = src.read_u32_le("DrawGdiPlus::gdipVersion")?;
        let draw_gdi_plus_cache_level = src.read_u32_le("DrawGdiPlus::cacheLevel")?;
        let mut gdip_cache_entries = [0u8; 20];
        gdip_cache_entries.copy_from_slice(src.read_slice(20, "DrawGdiPlus::cacheEntries")?);
        let mut gdip_cache_chunk_size = [0u8; 16];
        gdip_cache_chunk_size.copy_from_slice(src.read_slice(16, "DrawGdiPlus::cacheChunkSize")?);
        let mut gdip_image_cache_properties = [0u8; 12];
        gdip_image_cache_properties.copy_from_slice(src.read_slice(12, "DrawGdiPlus::imageCacheProperties")?);
        Ok(Self {
            draw_gdi_plus_support_level, gdip_version, draw_gdi_plus_cache_level,
            gdip_cache_entries, gdip_cache_chunk_size, gdip_image_cache_properties,
        })
    }
}

/// Remote Programs (RAIL) Capability Set (MS-RDPBCGR 2.2.7.2.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RailCapability {
    pub rail_support_level: u32,
}

const RAIL_BODY_SIZE: usize = 4;

impl Encode for RailCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.rail_support_level, "Rail::railSupportLevel")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "RailCapability" }
    fn size(&self) -> usize { RAIL_BODY_SIZE }
}

impl<'de> Decode<'de> for RailCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            rail_support_level: src.read_u32_le("Rail::railSupportLevel")?,
        })
    }
}

/// Window List Capability Set (MS-RDPBCGR 2.2.7.2.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowCapability {
    pub wnd_support_level: u32,
    pub num_icon_caches: u8,
    pub num_icon_cache_entries: u16,
}

const WINDOW_BODY_SIZE: usize = 7;

impl Encode for WindowCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.wnd_support_level, "Window::wndSupportLevel")?;
        dst.write_u8(self.num_icon_caches, "Window::numIconCaches")?;
        dst.write_u16_le(self.num_icon_cache_entries, "Window::numIconCacheEntries")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "WindowCapability" }
    fn size(&self) -> usize { WINDOW_BODY_SIZE }
}

impl<'de> Decode<'de> for WindowCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            wnd_support_level: src.read_u32_le("Window::wndSupportLevel")?,
            num_icon_caches: src.read_u8("Window::numIconCaches")?,
            num_icon_cache_entries: src.read_u16_le("Window::numIconCacheEntries")?,
        })
    }
}

/// Desktop Composition Capability Set (MS-RDPBCGR 2.2.7.2.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopCompositionCapability {
    pub comp_desk_support_level: u16,
}

const DESKTOP_COMPOSITION_BODY_SIZE: usize = 2;

impl Encode for DesktopCompositionCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.comp_desk_support_level, "DesktopComposition::compDeskSupportLevel")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "DesktopCompositionCapability" }
    fn size(&self) -> usize { DESKTOP_COMPOSITION_BODY_SIZE }
}

impl<'de> Decode<'de> for DesktopCompositionCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            comp_desk_support_level: src.read_u16_le("DesktopComposition::compDeskSupportLevel")?,
        })
    }
}

/// Multifragment Update Capability Set (MS-RDPBCGR 2.2.7.2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultifragmentUpdateCapability {
    pub max_request_size: u32,
}

const MULTIFRAGMENT_UPDATE_BODY_SIZE: usize = 4;

impl Encode for MultifragmentUpdateCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.max_request_size, "MultifragmentUpdate::maxRequestSize")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "MultifragmentUpdateCapability" }
    fn size(&self) -> usize { MULTIFRAGMENT_UPDATE_BODY_SIZE }
}

impl<'de> Decode<'de> for MultifragmentUpdateCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            max_request_size: src.read_u32_le("MultifragmentUpdate::maxRequestSize")?,
        })
    }
}

/// Large Pointer Capability Set (MS-RDPBCGR 2.2.7.2.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LargePointerCapability {
    pub large_pointer_support_flags: u16,
}

const LARGE_POINTER_BODY_SIZE: usize = 2;

impl Encode for LargePointerCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.large_pointer_support_flags, "LargePointer::flags")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "LargePointerCapability" }
    fn size(&self) -> usize { LARGE_POINTER_BODY_SIZE }
}

impl<'de> Decode<'de> for LargePointerCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            large_pointer_support_flags: src.read_u16_le("LargePointer::flags")?,
        })
    }
}

/// Surface Commands Capability Set (MS-RDPBCGR 2.2.7.2.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceCommandsCapability {
    pub cmd_flags: u32,
    pub reserved: u32,
}

const SURFACE_COMMANDS_BODY_SIZE: usize = 8;

impl Encode for SurfaceCommandsCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.cmd_flags, "SurfaceCommands::cmdFlags")?;
        dst.write_u32_le(self.reserved, "SurfaceCommands::reserved")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "SurfaceCommandsCapability" }
    fn size(&self) -> usize { SURFACE_COMMANDS_BODY_SIZE }
}

impl<'de> Decode<'de> for SurfaceCommandsCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            cmd_flags: src.read_u32_le("SurfaceCommands::cmdFlags")?,
            reserved: src.read_u32_le("SurfaceCommands::reserved")?,
        })
    }
}

/// Bitmap Codecs Capability Set (MS-RDPBCGR 2.2.7.2.10).
///
/// The internal structure is variable-length and complex; stored as raw bytes for now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapCodecsCapability {
    pub supported_bitmap_codecs: Vec<u8>,
}

impl Encode for BitmapCodecsCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_slice(&self.supported_bitmap_codecs, "BitmapCodecs::data")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "BitmapCodecsCapability" }
    fn size(&self) -> usize { self.supported_bitmap_codecs.len() }
}

impl BitmapCodecsCapability {
    pub fn decode_with_len(src: &mut ReadCursor<'_>, body_len: usize) -> DecodeResult<Self> {
        let data = src.read_slice(body_len, "BitmapCodecs::data")?;
        Ok(Self { supported_bitmap_codecs: data.into() })
    }
}

/// Frame Acknowledge Capability Set (MS-RDPBCGR 2.2.7.2.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameAcknowledgeCapability {
    pub max_unacknowledged_frame_count: u32,
}

const FRAME_ACKNOWLEDGE_BODY_SIZE: usize = 4;

impl Encode for FrameAcknowledgeCapability {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.max_unacknowledged_frame_count, "FrameAck::maxUnacknowledgedFrameCount")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "FrameAcknowledgeCapability" }
    fn size(&self) -> usize { FRAME_ACKNOWLEDGE_BODY_SIZE }
}

impl<'de> Decode<'de> for FrameAcknowledgeCapability {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            max_unacknowledged_frame_count: src.read_u32_le("FrameAck::maxUnacknowledgedFrameCount")?,
        })
    }
}

// ── CapabilitySet enum ──

/// A single capability set with its header dispatched to a concrete type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilitySet {
    General(GeneralCapability),
    Bitmap(BitmapCapability),
    Order(OrderCapability),
    BitmapCache(BitmapCacheCapability),
    BitmapCacheRev2(BitmapCacheRev2Capability),
    Control(ControlCapability),
    Activation(ActivationCapability),
    Pointer(PointerCapability),
    Share(ShareCapability),
    ColorCache(ColorCacheCapability),
    Sound(SoundCapability),
    Input(InputCapability),
    Font(FontCapability),
    Brush(BrushCapability),
    GlyphCache(GlyphCacheCapability),
    OffscreenCache(OffscreenCacheCapability),
    BitmapCacheHostSupport(BitmapCacheHostSupportCapability),
    VirtualChannel(VirtualChannelCapability),
    DrawNineGridCache(DrawNineGridCacheCapability),
    DrawGdiPlus(DrawGdiPlusCapability),
    Rail(RailCapability),
    Window(WindowCapability),
    DesktopComposition(DesktopCompositionCapability),
    MultifragmentUpdate(MultifragmentUpdateCapability),
    LargePointer(LargePointerCapability),
    SurfaceCommands(SurfaceCommandsCapability),
    BitmapCodecs(BitmapCodecsCapability),
    FrameAcknowledge(FrameAcknowledgeCapability),
    /// Unrecognized capability type -- preserved as raw bytes.
    Unknown { cap_type: u16, data: Vec<u8> },
}

impl CapabilitySet {
    /// Returns the capability set type code for the header.
    pub fn cap_type(&self) -> u16 {
        match self {
            CapabilitySet::General(_) => CapabilitySetType::General as u16,
            CapabilitySet::Bitmap(_) => CapabilitySetType::Bitmap as u16,
            CapabilitySet::Order(_) => CapabilitySetType::Order as u16,
            CapabilitySet::BitmapCache(_) => CapabilitySetType::BitmapCache as u16,
            CapabilitySet::BitmapCacheRev2(_) => CapabilitySetType::BitmapCacheRev2 as u16,
            CapabilitySet::Control(_) => CapabilitySetType::Control as u16,
            CapabilitySet::Activation(_) => CapabilitySetType::Activation as u16,
            CapabilitySet::Pointer(_) => CapabilitySetType::Pointer as u16,
            CapabilitySet::Share(_) => CapabilitySetType::Share as u16,
            CapabilitySet::ColorCache(_) => CapabilitySetType::ColorCache as u16,
            CapabilitySet::Sound(_) => CapabilitySetType::Sound as u16,
            CapabilitySet::Input(_) => CapabilitySetType::Input as u16,
            CapabilitySet::Font(_) => CapabilitySetType::Font as u16,
            CapabilitySet::Brush(_) => CapabilitySetType::Brush as u16,
            CapabilitySet::GlyphCache(_) => CapabilitySetType::GlyphCache as u16,
            CapabilitySet::OffscreenCache(_) => CapabilitySetType::OffscreenCache as u16,
            CapabilitySet::BitmapCacheHostSupport(_) => CapabilitySetType::BitmapCacheHostSupport as u16,
            CapabilitySet::VirtualChannel(_) => CapabilitySetType::VirtualChannel as u16,
            CapabilitySet::DrawNineGridCache(_) => CapabilitySetType::DrawNineGridCache as u16,
            CapabilitySet::DrawGdiPlus(_) => CapabilitySetType::DrawGdiPlus as u16,
            CapabilitySet::Rail(_) => CapabilitySetType::Rail as u16,
            CapabilitySet::Window(_) => CapabilitySetType::Window as u16,
            CapabilitySet::DesktopComposition(_) => CapabilitySetType::DesktopComposition as u16,
            CapabilitySet::MultifragmentUpdate(_) => CapabilitySetType::MultifragmentUpdate as u16,
            CapabilitySet::LargePointer(_) => CapabilitySetType::LargePointer as u16,
            CapabilitySet::SurfaceCommands(_) => CapabilitySetType::SurfaceCommands as u16,
            CapabilitySet::BitmapCodecs(_) => CapabilitySetType::BitmapCodecs as u16,
            CapabilitySet::FrameAcknowledge(_) => CapabilitySetType::FrameAcknowledge as u16,
            CapabilitySet::Unknown { cap_type, .. } => *cap_type,
        }
    }

    /// Returns the encoded body size (without the 4-byte header).
    fn body_size(&self) -> usize {
        match self {
            CapabilitySet::General(c) => c.size(),
            CapabilitySet::Bitmap(c) => c.size(),
            CapabilitySet::Order(c) => c.size(),
            CapabilitySet::BitmapCache(c) => c.size(),
            CapabilitySet::BitmapCacheRev2(c) => c.size(),
            CapabilitySet::Control(c) => c.size(),
            CapabilitySet::Activation(c) => c.size(),
            CapabilitySet::Pointer(c) => c.size(),
            CapabilitySet::Share(c) => c.size(),
            CapabilitySet::ColorCache(c) => c.size(),
            CapabilitySet::Sound(c) => c.size(),
            CapabilitySet::Input(c) => c.size(),
            CapabilitySet::Font(c) => c.size(),
            CapabilitySet::Brush(c) => c.size(),
            CapabilitySet::GlyphCache(c) => c.size(),
            CapabilitySet::OffscreenCache(c) => c.size(),
            CapabilitySet::BitmapCacheHostSupport(c) => c.size(),
            CapabilitySet::VirtualChannel(c) => c.size(),
            CapabilitySet::DrawNineGridCache(c) => c.size(),
            CapabilitySet::DrawGdiPlus(c) => c.size(),
            CapabilitySet::Rail(c) => c.size(),
            CapabilitySet::Window(c) => c.size(),
            CapabilitySet::DesktopComposition(c) => c.size(),
            CapabilitySet::MultifragmentUpdate(c) => c.size(),
            CapabilitySet::LargePointer(c) => c.size(),
            CapabilitySet::SurfaceCommands(c) => c.size(),
            CapabilitySet::BitmapCodecs(c) => c.size(),
            CapabilitySet::FrameAcknowledge(c) => c.size(),
            CapabilitySet::Unknown { data, .. } => data.len(),
        }
    }
}

/// Read a single capability set (header + body) from the cursor.
pub fn read_capability_set(src: &mut ReadCursor<'_>) -> DecodeResult<CapabilitySet> {
    let cap_type_raw = src.read_u16_le("CapabilitySet::capabilitySetType")?;
    let length = src.read_u16_le("CapabilitySet::lengthCapability")? as usize;

    if length < CAPABILITY_HEADER_SIZE {
        return Err(DecodeError::invalid_value("CapabilitySet", "lengthCapability"));
    }

    let body_len = length - CAPABILITY_HEADER_SIZE;

    match CapabilitySetType::from_u16(cap_type_raw) {
        Some(CapabilitySetType::General) => Ok(CapabilitySet::General(GeneralCapability::decode(src)?)),
        Some(CapabilitySetType::Bitmap) => Ok(CapabilitySet::Bitmap(BitmapCapability::decode(src)?)),
        Some(CapabilitySetType::Order) => Ok(CapabilitySet::Order(OrderCapability::decode(src)?)),
        Some(CapabilitySetType::BitmapCache) => Ok(CapabilitySet::BitmapCache(BitmapCacheCapability::decode(src)?)),
        Some(CapabilitySetType::Control) => Ok(CapabilitySet::Control(ControlCapability::decode(src)?)),
        Some(CapabilitySetType::Activation) => Ok(CapabilitySet::Activation(ActivationCapability::decode(src)?)),
        Some(CapabilitySetType::Pointer) => Ok(CapabilitySet::Pointer(PointerCapability::decode(src)?)),
        Some(CapabilitySetType::Share) => Ok(CapabilitySet::Share(ShareCapability::decode(src)?)),
        Some(CapabilitySetType::ColorCache) => Ok(CapabilitySet::ColorCache(ColorCacheCapability::decode(src)?)),
        Some(CapabilitySetType::Sound) => Ok(CapabilitySet::Sound(SoundCapability::decode(src)?)),
        Some(CapabilitySetType::Input) => Ok(CapabilitySet::Input(InputCapability::decode(src)?)),
        Some(CapabilitySetType::Font) => Ok(CapabilitySet::Font(FontCapability::decode(src)?)),
        Some(CapabilitySetType::Brush) => Ok(CapabilitySet::Brush(BrushCapability::decode(src)?)),
        Some(CapabilitySetType::GlyphCache) => Ok(CapabilitySet::GlyphCache(GlyphCacheCapability::decode(src)?)),
        Some(CapabilitySetType::OffscreenCache) => Ok(CapabilitySet::OffscreenCache(OffscreenCacheCapability::decode(src)?)),
        Some(CapabilitySetType::BitmapCacheHostSupport) => Ok(CapabilitySet::BitmapCacheHostSupport(BitmapCacheHostSupportCapability::decode(src)?)),
        Some(CapabilitySetType::BitmapCacheRev2) => Ok(CapabilitySet::BitmapCacheRev2(BitmapCacheRev2Capability::decode(src)?)),
        Some(CapabilitySetType::VirtualChannel) => Ok(CapabilitySet::VirtualChannel(VirtualChannelCapability::decode_with_len(src, body_len)?)),
        Some(CapabilitySetType::DrawNineGridCache) => Ok(CapabilitySet::DrawNineGridCache(DrawNineGridCacheCapability::decode(src)?)),
        Some(CapabilitySetType::DrawGdiPlus) => Ok(CapabilitySet::DrawGdiPlus(DrawGdiPlusCapability::decode(src)?)),
        Some(CapabilitySetType::Rail) => Ok(CapabilitySet::Rail(RailCapability::decode(src)?)),
        Some(CapabilitySetType::Window) => Ok(CapabilitySet::Window(WindowCapability::decode(src)?)),
        Some(CapabilitySetType::DesktopComposition) => Ok(CapabilitySet::DesktopComposition(DesktopCompositionCapability::decode(src)?)),
        Some(CapabilitySetType::MultifragmentUpdate) => Ok(CapabilitySet::MultifragmentUpdate(MultifragmentUpdateCapability::decode(src)?)),
        Some(CapabilitySetType::LargePointer) => Ok(CapabilitySet::LargePointer(LargePointerCapability::decode(src)?)),
        Some(CapabilitySetType::SurfaceCommands) => Ok(CapabilitySet::SurfaceCommands(SurfaceCommandsCapability::decode(src)?)),
        Some(CapabilitySetType::BitmapCodecs) => Ok(CapabilitySet::BitmapCodecs(BitmapCodecsCapability::decode_with_len(src, body_len)?)),
        Some(CapabilitySetType::FrameAcknowledge) => Ok(CapabilitySet::FrameAcknowledge(FrameAcknowledgeCapability::decode(src)?)),
        None => {
            let data = src.read_slice(body_len, "CapabilitySet::unknown_body")?.into();
            Ok(CapabilitySet::Unknown { cap_type: cap_type_raw, data })
        }
    }
}

/// Write a single capability set (header + body) to the cursor.
pub fn write_capability_set(cap: &CapabilitySet, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
    let body_size = cap.body_size();
    let total_len = CAPABILITY_HEADER_SIZE + body_size;

    dst.write_u16_le(cap.cap_type(), "CapabilitySet::capabilitySetType")?;
    dst.write_u16_le(total_len as u16, "CapabilitySet::lengthCapability")?;

    match cap {
        CapabilitySet::General(c) => c.encode(dst),
        CapabilitySet::Bitmap(c) => c.encode(dst),
        CapabilitySet::Order(c) => c.encode(dst),
        CapabilitySet::BitmapCache(c) => c.encode(dst),
        CapabilitySet::BitmapCacheRev2(c) => c.encode(dst),
        CapabilitySet::Control(c) => c.encode(dst),
        CapabilitySet::Activation(c) => c.encode(dst),
        CapabilitySet::Pointer(c) => c.encode(dst),
        CapabilitySet::Share(c) => c.encode(dst),
        CapabilitySet::ColorCache(c) => c.encode(dst),
        CapabilitySet::Sound(c) => c.encode(dst),
        CapabilitySet::Input(c) => c.encode(dst),
        CapabilitySet::Font(c) => c.encode(dst),
        CapabilitySet::Brush(c) => c.encode(dst),
        CapabilitySet::GlyphCache(c) => c.encode(dst),
        CapabilitySet::OffscreenCache(c) => c.encode(dst),
        CapabilitySet::BitmapCacheHostSupport(c) => c.encode(dst),
        CapabilitySet::VirtualChannel(c) => c.encode(dst),
        CapabilitySet::DrawNineGridCache(c) => c.encode(dst),
        CapabilitySet::DrawGdiPlus(c) => c.encode(dst),
        CapabilitySet::Rail(c) => c.encode(dst),
        CapabilitySet::Window(c) => c.encode(dst),
        CapabilitySet::DesktopComposition(c) => c.encode(dst),
        CapabilitySet::MultifragmentUpdate(c) => c.encode(dst),
        CapabilitySet::LargePointer(c) => c.encode(dst),
        CapabilitySet::SurfaceCommands(c) => c.encode(dst),
        CapabilitySet::BitmapCodecs(c) => c.encode(dst),
        CapabilitySet::FrameAcknowledge(c) => c.encode(dst),
        CapabilitySet::Unknown { data, .. } => dst.write_slice(data, "CapabilitySet::unknown_body"),
    }
}

/// Total encoded size of a capability set including header.
pub fn capability_set_size(cap: &CapabilitySet) -> usize {
    CAPABILITY_HEADER_SIZE + cap.body_size()
}

// ── Demand Active PDU ──

/// Server Demand Active PDU (MS-RDPBCGR 2.2.1.13.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemandActivePdu {
    pub share_id: u32,
    pub source_descriptor: Vec<u8>,
    pub capability_sets: Vec<CapabilitySet>,
    pub session_id: u32,
}

impl Encode for DemandActivePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.share_id, "DemandActive::shareId")?;

        let source_desc_len = self.source_descriptor.len() as u16;
        dst.write_u16_le(source_desc_len, "DemandActive::lengthSourceDescriptor")?;

        // Compute combined capabilities length: numberCapabilities(2) + pad2(2) + all cap sets
        let caps_body_size: usize = self.capability_sets.iter().map(capability_set_size).sum();
        let combined_len = (4 + caps_body_size) as u16;
        dst.write_u16_le(combined_len, "DemandActive::lengthCombinedCapabilities")?;

        dst.write_slice(&self.source_descriptor, "DemandActive::sourceDescriptor")?;

        dst.write_u16_le(self.capability_sets.len() as u16, "DemandActive::numberCapabilities")?;
        dst.write_u16_le(0, "DemandActive::pad2")?;

        for cap in &self.capability_sets {
            write_capability_set(cap, dst)?;
        }

        dst.write_u32_le(self.session_id, "DemandActive::sessionId")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "DemandActivePdu" }

    fn size(&self) -> usize {
        let caps_size: usize = self.capability_sets.iter().map(capability_set_size).sum();
        // shareId(4) + lengthSourceDescriptor(2) + lengthCombinedCapabilities(2)
        // + sourceDescriptor(var) + numberCapabilities(2) + pad2(2)
        // + capabilitySets(var) + sessionId(4)
        4 + 2 + 2 + self.source_descriptor.len() + 2 + 2 + caps_size + 4
    }
}

impl<'de> Decode<'de> for DemandActivePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let share_id = src.read_u32_le("DemandActive::shareId")?;
        let source_desc_len = src.read_u16_le("DemandActive::lengthSourceDescriptor")? as usize;
        let _combined_len = src.read_u16_le("DemandActive::lengthCombinedCapabilities")?;
        let source_descriptor = src.read_slice(source_desc_len, "DemandActive::sourceDescriptor")?.into();
        let num_caps = src.read_u16_le("DemandActive::numberCapabilities")? as usize;
        let _pad2 = src.read_u16_le("DemandActive::pad2")?;

        let mut capability_sets = Vec::with_capacity(num_caps);
        for _ in 0..num_caps {
            capability_sets.push(read_capability_set(src)?);
        }

        let session_id = src.read_u32_le("DemandActive::sessionId")?;
        Ok(Self { share_id, source_descriptor, capability_sets, session_id })
    }
}

// ── Confirm Active PDU ──

/// Client Confirm Active PDU (MS-RDPBCGR 2.2.1.13.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmActivePdu {
    pub share_id: u32,
    pub originator_id: u16,
    pub source_descriptor: Vec<u8>,
    pub capability_sets: Vec<CapabilitySet>,
}

impl Encode for ConfirmActivePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.share_id, "ConfirmActive::shareId")?;
        dst.write_u16_le(self.originator_id, "ConfirmActive::originatorId")?;

        let source_desc_len = self.source_descriptor.len() as u16;
        dst.write_u16_le(source_desc_len, "ConfirmActive::lengthSourceDescriptor")?;

        let caps_body_size: usize = self.capability_sets.iter().map(capability_set_size).sum();
        let combined_len = (4 + caps_body_size) as u16;
        dst.write_u16_le(combined_len, "ConfirmActive::lengthCombinedCapabilities")?;

        dst.write_slice(&self.source_descriptor, "ConfirmActive::sourceDescriptor")?;

        dst.write_u16_le(self.capability_sets.len() as u16, "ConfirmActive::numberCapabilities")?;
        dst.write_u16_le(0, "ConfirmActive::pad2")?;

        for cap in &self.capability_sets {
            write_capability_set(cap, dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str { "ConfirmActivePdu" }

    fn size(&self) -> usize {
        let caps_size: usize = self.capability_sets.iter().map(capability_set_size).sum();
        // shareId(4) + originatorId(2) + lengthSourceDescriptor(2) + lengthCombinedCapabilities(2)
        // + sourceDescriptor(var) + numberCapabilities(2) + pad2(2) + capabilitySets(var)
        4 + 2 + 2 + 2 + self.source_descriptor.len() + 2 + 2 + caps_size
    }
}

impl<'de> Decode<'de> for ConfirmActivePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let share_id = src.read_u32_le("ConfirmActive::shareId")?;
        let originator_id = src.read_u16_le("ConfirmActive::originatorId")?;
        let source_desc_len = src.read_u16_le("ConfirmActive::lengthSourceDescriptor")? as usize;
        let _combined_len = src.read_u16_le("ConfirmActive::lengthCombinedCapabilities")?;
        let source_descriptor = src.read_slice(source_desc_len, "ConfirmActive::sourceDescriptor")?.into();
        let num_caps = src.read_u16_le("ConfirmActive::numberCapabilities")? as usize;
        let _pad2 = src.read_u16_le("ConfirmActive::pad2")?;

        let mut capability_sets = Vec::with_capacity(num_caps);
        for _ in 0..num_caps {
            capability_sets.push(read_capability_set(src)?);
        }

        Ok(Self { share_id, originator_id, source_descriptor, capability_sets })
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Helper: encode then decode and check equality.
    fn roundtrip_capability(cap: CapabilitySet) -> CapabilitySet {
        let size = capability_set_size(&cap);
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        write_capability_set(&cap, &mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        read_capability_set(&mut cursor).unwrap()
    }

    #[test]
    fn general_roundtrip() {
        let cap = CapabilitySet::General(GeneralCapability {
            os_major_type: 1,
            os_minor_type: 3,
            protocol_version: 0x0200,
            pad2: 0,
            general_compression_types: 0,
            extra_flags: 0x041D,
            update_capability_flag: 0,
            remote_unshare_flag: 0,
            general_compression_level: 0,
            refresh_rect_support: 1,
            suppress_output_support: 1,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn bitmap_roundtrip() {
        let cap = CapabilitySet::Bitmap(BitmapCapability {
            preferred_bits_per_pixel: 32,
            receive1_bit_per_pixel: 1,
            receive4_bits_per_pixel: 1,
            receive8_bits_per_pixel: 1,
            desktop_width: 1920,
            desktop_height: 1080,
            pad2a: 0,
            desktop_resize_flag: 1,
            bitmap_compression_flag: 1,
            high_color_flags: 0,
            drawing_flags: 0x08,
            multiple_rectangle_support: 1,
            pad2b: 0,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn order_roundtrip() {
        let mut order_support = [0u8; 32];
        order_support[0] = 1;
        order_support[1] = 1;
        order_support[8] = 1;

        let cap = CapabilitySet::Order(OrderCapability {
            terminal_descriptor: [0u8; 16],
            pad4: 0,
            desktop_save_x_granularity: 1,
            desktop_save_y_granularity: 20,
            pad2a: 0,
            maximum_order_level: 1,
            number_fonts: 0,
            order_flags: 0x002A,
            order_support,
            text_flags: 0,
            order_support_ex_flags: 0,
            pad4b: 0,
            desktop_save_size: 480 * 480,
            pad2b: 0,
            pad2c: 0,
            text_ansi_code_page: 0x04E4,
            pad2d: 0,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn input_roundtrip() {
        let cap = CapabilitySet::Input(InputCapability {
            input_flags: 0x0031,
            pad2: 0,
            keyboard_layout: 0x00000409,
            keyboard_type: 4,
            keyboard_sub_type: 0,
            keyboard_function_key: 12,
            ime_file_name: [0u8; 64],
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn pointer_roundtrip() {
        let cap = CapabilitySet::Pointer(PointerCapability {
            color_pointer_flag: 1,
            color_pointer_cache_size: 25,
            pointer_cache_size: 25,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn control_roundtrip() {
        let cap = CapabilitySet::Control(ControlCapability {
            control_flags: 0,
            remote_detach_flag: 0,
            control_interest: 2,
            detach_interest: 2,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn activation_roundtrip() {
        let cap = CapabilitySet::Activation(ActivationCapability {
            help_key_flag: 0,
            help_key_index_flag: 0,
            help_extended_key_flag: 0,
            window_manager_key_flag: 0,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn share_roundtrip() {
        let cap = CapabilitySet::Share(ShareCapability { node_id: 0x03EA, pad2: 0 });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn color_cache_roundtrip() {
        let cap = CapabilitySet::ColorCache(ColorCacheCapability { color_table_cache_size: 6, pad2: 0 });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn sound_roundtrip() {
        let cap = CapabilitySet::Sound(SoundCapability { sound_flags: 1, pad2: 0 });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn font_roundtrip() {
        let cap = CapabilitySet::Font(FontCapability { font_support_flags: 1, pad2: 0 });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn brush_roundtrip() {
        let cap = CapabilitySet::Brush(BrushCapability { brush_support_level: 2 });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn glyph_cache_roundtrip() {
        let cap = CapabilitySet::GlyphCache(GlyphCacheCapability {
            glyph_cache: [0xAB; 40],
            frag_cache: 0x00010100,
            glyph_support_level: 2,
            pad2: 0,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn offscreen_cache_roundtrip() {
        let cap = CapabilitySet::OffscreenCache(OffscreenCacheCapability {
            offscreen_support_level: 1,
            offscreen_cache_size: 7680,
            offscreen_cache_entries: 500,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn bitmap_cache_host_support_roundtrip() {
        let cap = CapabilitySet::BitmapCacheHostSupport(BitmapCacheHostSupportCapability {
            cache_version: 1,
            pad1: 0,
            pad2: 0,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn bitmap_cache_roundtrip() {
        let cap = CapabilitySet::BitmapCache(BitmapCacheCapability {
            pad1: 0, pad2: 0, pad3: 0, pad4: 0, pad5: 0, pad6: 0,
            cache0_entries: 200, cache0_max_cell_size: 256,
            cache1_entries: 600, cache1_max_cell_size: 1024,
            cache2_entries: 1000, cache2_max_cell_size: 4096,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn bitmap_cache_rev2_roundtrip() {
        let cap = CapabilitySet::BitmapCacheRev2(BitmapCacheRev2Capability {
            cache_flags: 3,
            pad2: 0,
            num_cell_caches: 3,
            bitmap_cache0_cell_info: 0x00000078,
            bitmap_cache1_cell_info: 0x00000078,
            bitmap_cache2_cell_info: 0x00000078,
            bitmap_cache3_cell_info: 0,
            bitmap_cache4_cell_info: 0,
            pad3: [0; 12],
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn virtual_channel_roundtrip() {
        let cap = CapabilitySet::VirtualChannel(VirtualChannelCapability {
            flags: 0,
            vc_chunk_size: Some(1600),
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn virtual_channel_no_chunk_size_roundtrip() {
        let cap = CapabilitySet::VirtualChannel(VirtualChannelCapability {
            flags: 1,
            vc_chunk_size: None,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn draw_nine_grid_cache_roundtrip() {
        let cap = CapabilitySet::DrawNineGridCache(DrawNineGridCacheCapability {
            draw_nine_grid_support_level: 2,
            draw_nine_grid_cache_size: 2560,
            draw_nine_grid_cache_entries: 256,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn draw_gdi_plus_roundtrip() {
        let cap = CapabilitySet::DrawGdiPlus(DrawGdiPlusCapability {
            draw_gdi_plus_support_level: 0,
            gdip_version: 0,
            draw_gdi_plus_cache_level: 0,
            gdip_cache_entries: [0; 20],
            gdip_cache_chunk_size: [0; 16],
            gdip_image_cache_properties: [0; 12],
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn rail_roundtrip() {
        let cap = CapabilitySet::Rail(RailCapability { rail_support_level: 0 });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn window_roundtrip() {
        let cap = CapabilitySet::Window(WindowCapability {
            wnd_support_level: 2,
            num_icon_caches: 3,
            num_icon_cache_entries: 12,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn desktop_composition_roundtrip() {
        let cap = CapabilitySet::DesktopComposition(DesktopCompositionCapability {
            comp_desk_support_level: 1,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn multifragment_update_roundtrip() {
        let cap = CapabilitySet::MultifragmentUpdate(MultifragmentUpdateCapability {
            max_request_size: 0x00038400,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn large_pointer_roundtrip() {
        let cap = CapabilitySet::LargePointer(LargePointerCapability {
            large_pointer_support_flags: 1,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn surface_commands_roundtrip() {
        let cap = CapabilitySet::SurfaceCommands(SurfaceCommandsCapability {
            cmd_flags: 0x0000002C,
            reserved: 0,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn bitmap_codecs_roundtrip() {
        let cap = CapabilitySet::BitmapCodecs(BitmapCodecsCapability {
            supported_bitmap_codecs: vec![0x01, 0x00, 0x00],
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn frame_acknowledge_roundtrip() {
        let cap = CapabilitySet::FrameAcknowledge(FrameAcknowledgeCapability {
            max_unacknowledged_frame_count: 2,
        });
        assert_eq!(roundtrip_capability(cap.clone()), cap);
    }

    #[test]
    fn unknown_capability_type_decoded_as_unknown() {
        // Type 0xFFFF is not recognized -- should be decoded as Unknown.
        let body = [0xDE, 0xAD, 0xBE, 0xEF];
        let total_len = (CAPABILITY_HEADER_SIZE + body.len()) as u16;
        let mut buf = vec![0u8; CAPABILITY_HEADER_SIZE + body.len()];
        let mut cursor = WriteCursor::new(&mut buf);
        cursor.write_u16_le(0xFFFF, "test::type").unwrap();
        cursor.write_u16_le(total_len, "test::len").unwrap();
        cursor.write_slice(&body, "test::body").unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let cap = read_capability_set(&mut cursor).unwrap();
        match cap {
            CapabilitySet::Unknown { cap_type, data } => {
                assert_eq!(cap_type, 0xFFFF);
                assert_eq!(data, body);
            }
            _ => panic!("Expected Unknown variant"),
        }
    }

    #[test]
    fn demand_active_pdu_roundtrip() {
        let pdu = DemandActivePdu {
            share_id: 0x000103EA,
            source_descriptor: vec![0x52, 0x44, 0x50, 0x00], // "RDP\0"
            capability_sets: vec![
                CapabilitySet::General(GeneralCapability {
                    os_major_type: 1,
                    os_minor_type: 3,
                    protocol_version: 0x0200,
                    pad2: 0,
                    general_compression_types: 0,
                    extra_flags: 0x041D,
                    update_capability_flag: 0,
                    remote_unshare_flag: 0,
                    general_compression_level: 0,
                    refresh_rect_support: 1,
                    suppress_output_support: 1,
                }),
                CapabilitySet::Pointer(PointerCapability {
                    color_pointer_flag: 1,
                    color_pointer_cache_size: 25,
                    pointer_cache_size: 25,
                }),
                CapabilitySet::Brush(BrushCapability { brush_support_level: 2 }),
            ],
            session_id: 0,
        };

        let size = pdu.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DemandActivePdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn confirm_active_pdu_roundtrip() {
        let pdu = ConfirmActivePdu {
            share_id: 0x000103EA,
            originator_id: 0x03EA,
            source_descriptor: vec![0x4D, 0x53, 0x54, 0x53, 0x43, 0x00], // "MSTSC\0"
            capability_sets: vec![
                CapabilitySet::Bitmap(BitmapCapability {
                    preferred_bits_per_pixel: 32,
                    receive1_bit_per_pixel: 1,
                    receive4_bits_per_pixel: 1,
                    receive8_bits_per_pixel: 1,
                    desktop_width: 1920,
                    desktop_height: 1080,
                    pad2a: 0,
                    desktop_resize_flag: 1,
                    bitmap_compression_flag: 1,
                    high_color_flags: 0,
                    drawing_flags: 0x08,
                    multiple_rectangle_support: 1,
                    pad2b: 0,
                }),
                CapabilitySet::Input(InputCapability {
                    input_flags: 0x0031,
                    pad2: 0,
                    keyboard_layout: 0x00000409,
                    keyboard_type: 4,
                    keyboard_sub_type: 0,
                    keyboard_function_key: 12,
                    ime_file_name: [0u8; 64],
                }),
                CapabilitySet::Sound(SoundCapability { sound_flags: 1, pad2: 0 }),
                CapabilitySet::FrameAcknowledge(FrameAcknowledgeCapability {
                    max_unacknowledged_frame_count: 2,
                }),
            ],
        };

        let size = pdu.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConfirmActivePdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
    }
}
