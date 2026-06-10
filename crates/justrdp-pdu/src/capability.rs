//! Capability sets and the Demand Active / Confirm Active PDUs (MS-RDPBCGR 2.2.7 / 2.2.1.13) —
//! the second half of `capability-exchange`, after MCS/GCC.
//!
//! Typed structs cover the sets the connect sequence and the differential criteria actually
//! consume (General, Bitmap, Order, Pointer, Input, Virtual Channel, Bitmap Codecs); everything
//! else round-trips as [`CapabilitySet::Unknown`] raw bytes, because the negotiation rule for
//! unrecognized sets is "ignore, never reject" (MS-RDPBCGR 3.2.5.3.13).

use crate::DecodeError;
use crate::cursor::ReadCursor;

/// `capabilitySetType`: General.
pub const CAPSET_GENERAL: u16 = 0x0001;
/// `capabilitySetType`: Bitmap.
pub const CAPSET_BITMAP: u16 = 0x0002;
/// `capabilitySetType`: Order.
pub const CAPSET_ORDER: u16 = 0x0003;
/// `capabilitySetType`: Bitmap Cache (revision 1).
pub const CAPSET_BITMAP_CACHE: u16 = 0x0004;
/// `capabilitySetType`: Pointer.
pub const CAPSET_POINTER: u16 = 0x0008;
/// `capabilitySetType`: Sound.
pub const CAPSET_SOUND: u16 = 0x000C;
/// `capabilitySetType`: Input.
pub const CAPSET_INPUT: u16 = 0x000D;
/// `capabilitySetType`: Brush.
pub const CAPSET_BRUSH: u16 = 0x000F;
/// `capabilitySetType`: Glyph Cache.
pub const CAPSET_GLYPH_CACHE: u16 = 0x0010;
/// `capabilitySetType`: Offscreen Bitmap Cache.
pub const CAPSET_OFFSCREEN_CACHE: u16 = 0x0011;
/// `capabilitySetType`: Virtual Channel.
pub const CAPSET_VIRTUAL_CHANNEL: u16 = 0x0014;
/// `capabilitySetType`: Bitmap Codecs.
pub const CAPSET_BITMAP_CODECS: u16 = 0x001D;

/// `extraFlags`: fast-path output supported.
pub const GENERAL_FASTPATH_OUTPUT_SUPPORTED: u16 = 0x0001;
/// `extraFlags`: long credentials supported.
pub const GENERAL_LONG_CREDENTIALS_SUPPORTED: u16 = 0x0004;
/// `extraFlags`: no bitmap compression header.
pub const GENERAL_NO_BITMAP_COMPRESSION_HDR: u16 = 0x0400;

/// `inputFlags`: scancode input events (mandatory).
pub const INPUT_FLAG_SCANCODES: u16 = 0x0001;
/// `inputFlags`: extended mouse-button (MouseX) events.
pub const INPUT_FLAG_MOUSEX: u16 = 0x0004;
/// `inputFlags`: Unicode keyboard events.
pub const INPUT_FLAG_UNICODE: u16 = 0x0010;
/// `inputFlags`: fast-path input events. Server-advertised (in Demand Active); the client
/// sends fast-path input only when the server set this or [`INPUT_FLAG_FASTPATH_INPUT2`].
pub const INPUT_FLAG_FASTPATH_INPUT: u16 = 0x0008;
/// `inputFlags`: fast-path input v2 (CredSSP-era servers advertise this form).
pub const INPUT_FLAG_FASTPATH_INPUT2: u16 = 0x0020;
/// `inputFlags`: horizontal mouse wheel events (`TS_INPUT_FLAG_MOUSE_HWHEEL`).
pub const INPUT_FLAG_MOUSE_HWHEEL: u16 = 0x0100;

/// `orderFlags`: order negotiation supported (MUST be set).
pub const ORDER_NEGOTIATE_SUPPORT: u16 = 0x0002;
/// `orderFlags`: zero bounds deltas supported (MUST be set).
pub const ORDER_ZERO_BOUNDS_DELTAS_SUPPORT: u16 = 0x0008;

/// General Capability Set (TS_GENERAL_CAPABILITYSET, 2.2.7.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GeneralCapabilitySet {
    /// `osMajorType` (1 = Windows).
    pub os_major_type: u16,
    /// `osMinorType` (3 = Windows NT).
    pub os_minor_type: u16,
    /// `extraFlags` (`GENERAL_*` bits) — the Demand Active counterpart of GCC's
    /// `earlyCapabilityFlags` for output-path features.
    pub extra_flags: u16,
    /// `refreshRectSupport` (server-advertised).
    pub refresh_rect_support: u8,
    /// `suppressOutputSupport` (server-advertised).
    pub suppress_output_support: u8,
}

/// `protocolVersion` — always 0x0200.
const GENERAL_PROTOCOL_VERSION: u16 = 0x0200;

impl GeneralCapabilitySet {
    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.os_major_type.to_le_bytes());
        out.extend_from_slice(&self.os_minor_type.to_le_bytes());
        out.extend_from_slice(&GENERAL_PROTOCOL_VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // pad2octetsA
        out.extend_from_slice(&0u16.to_le_bytes()); // generalCompressionTypes
        out.extend_from_slice(&self.extra_flags.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // updateCapabilityFlag
        out.extend_from_slice(&0u16.to_le_bytes()); // remoteUnshareFlag
        out.extend_from_slice(&0u16.to_le_bytes()); // generalCompressionLevel
        out.push(self.refresh_rect_support);
        out.push(self.suppress_output_support);
    }

    fn decode_body(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let os_major_type = cur.read_u16_le()?;
        let os_minor_type = cur.read_u16_le()?;
        cur.read_u16_le()?; // protocolVersion
        cur.read_u16_le()?; // pad2octetsA
        cur.read_u16_le()?; // generalCompressionTypes
        let extra_flags = cur.read_u16_le()?;
        cur.read_u16_le()?; // updateCapabilityFlag
        cur.read_u16_le()?; // remoteUnshareFlag
        cur.read_u16_le()?; // generalCompressionLevel
        // Trailing support bytes are absent in pre-5.1 servers; default 0.
        let refresh_rect_support = cur.read_u8().unwrap_or(0);
        let suppress_output_support = cur.read_u8().unwrap_or(0);
        Ok(Self {
            os_major_type,
            os_minor_type,
            extra_flags,
            refresh_rect_support,
            suppress_output_support,
        })
    }
}

/// Bitmap Capability Set (TS_BITMAP_CAPABILITYSET, 2.2.7.1.2). The server's copy carries the
/// **negotiated desktop size**; the client echoes that size back in Confirm Active.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BitmapCapabilitySet {
    /// `preferredBitsPerPixel` — the negotiated color depth in the server's copy.
    pub preferred_bits_per_pixel: u16,
    /// `desktopWidth` — the negotiated width in the server's copy.
    pub desktop_width: u16,
    /// `desktopHeight` — the negotiated height in the server's copy.
    pub desktop_height: u16,
    /// `desktopResizeFlag` — whether desktop resizing is supported.
    pub desktop_resize_flag: u16,
    /// `drawingFlags`.
    pub drawing_flags: u8,
}

impl BitmapCapabilitySet {
    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.preferred_bits_per_pixel.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // receive1BitPerPixel (ignored, MUST 1)
        out.extend_from_slice(&1u16.to_le_bytes()); // receive4BitsPerPixel
        out.extend_from_slice(&1u16.to_le_bytes()); // receive8BitsPerPixel
        out.extend_from_slice(&self.desktop_width.to_le_bytes());
        out.extend_from_slice(&self.desktop_height.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // pad2octets
        out.extend_from_slice(&self.desktop_resize_flag.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // bitmapCompressionFlag (MUST 1)
        out.push(0); // highColorFlags (MUST 0)
        out.push(self.drawing_flags);
        out.extend_from_slice(&1u16.to_le_bytes()); // multipleRectangleSupport (MUST 1)
        out.extend_from_slice(&0u16.to_le_bytes()); // pad2octetsB
    }

    fn decode_body(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let preferred_bits_per_pixel = cur.read_u16_le()?;
        cur.read_u16_le()?; // receive1BitPerPixel
        cur.read_u16_le()?; // receive4BitsPerPixel
        cur.read_u16_le()?; // receive8BitsPerPixel
        let desktop_width = cur.read_u16_le()?;
        let desktop_height = cur.read_u16_le()?;
        cur.read_u16_le()?; // pad2octets
        let desktop_resize_flag = cur.read_u16_le()?;
        cur.read_u16_le()?; // bitmapCompressionFlag
        cur.read_u8()?; // highColorFlags
        let drawing_flags = cur.read_u8()?;
        // multipleRectangleSupport + pad may be truncated by old servers.
        let _ = cur.read_u16_le();
        let _ = cur.read_u16_le();
        Ok(Self {
            preferred_bits_per_pixel,
            desktop_width,
            desktop_height,
            desktop_resize_flag,
            drawing_flags,
        })
    }
}

/// Order Capability Set (TS_ORDER_CAPABILITYSET, 2.2.7.1.3). `order_support` indexes which
/// drawing orders the sender handles — all zeros means "send me bitmap updates instead",
/// which is exactly right until the orders epic (plan.md §7: false positives crash us).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderCapabilitySet {
    /// `orderFlags` (must include the two mandatory `ORDER_*` bits).
    pub order_flags: u16,
    /// `orderSupport[32]` — one byte per order type.
    pub order_support: [u8; 32],
    /// `desktopSaveSize` — save-bitmap buffer size (0: unsupported).
    pub desktop_save_size: u32,
}

impl Default for OrderCapabilitySet {
    fn default() -> Self {
        Self {
            order_flags: ORDER_NEGOTIATE_SUPPORT | ORDER_ZERO_BOUNDS_DELTAS_SUPPORT,
            order_support: [0; 32],
            desktop_save_size: 0,
        }
    }
}

impl OrderCapabilitySet {
    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[0u8; 16]); // terminalDescriptor (ignored)
        out.extend_from_slice(&0u32.to_le_bytes()); // pad4octetsA
        out.extend_from_slice(&1u16.to_le_bytes()); // desktopSaveXGranularity
        out.extend_from_slice(&20u16.to_le_bytes()); // desktopSaveYGranularity
        out.extend_from_slice(&0u16.to_le_bytes()); // pad2octetsA
        out.extend_from_slice(&1u16.to_le_bytes()); // maximumOrderLevel (ORD_LEVEL_1_ORDERS)
        out.extend_from_slice(&0u16.to_le_bytes()); // numberFonts (ignored)
        out.extend_from_slice(&self.order_flags.to_le_bytes());
        out.extend_from_slice(&self.order_support);
        out.extend_from_slice(&0u16.to_le_bytes()); // textFlags (ignored)
        out.extend_from_slice(&0u16.to_le_bytes()); // orderSupportExFlags
        out.extend_from_slice(&0u32.to_le_bytes()); // pad4octetsB
        out.extend_from_slice(&self.desktop_save_size.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // pad2octetsC
        out.extend_from_slice(&0u16.to_le_bytes()); // pad2octetsD
        out.extend_from_slice(&0u16.to_le_bytes()); // textANSICodePage
        out.extend_from_slice(&0u16.to_le_bytes()); // pad2octetsE
    }

    fn decode_body(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        cur.read_slice(16)?; // terminalDescriptor
        cur.read_u32_le()?; // pad4octetsA
        cur.read_u16_le()?; // desktopSaveXGranularity
        cur.read_u16_le()?; // desktopSaveYGranularity
        cur.read_u16_le()?; // pad2octetsA
        cur.read_u16_le()?; // maximumOrderLevel
        cur.read_u16_le()?; // numberFonts
        let order_flags = cur.read_u16_le()?;
        let mut order_support = [0u8; 32];
        order_support.copy_from_slice(cur.read_slice(32)?);
        cur.read_u16_le()?; // textFlags
        cur.read_u16_le()?; // orderSupportExFlags
        cur.read_u32_le()?; // pad4octetsB
        let desktop_save_size = cur.read_u32_le()?;
        // Remaining pads/code page may be truncated; nothing read from them.
        Ok(Self {
            order_flags,
            order_support,
            desktop_save_size,
        })
    }
}

/// Pointer Capability Set (TS_POINTER_CAPABILITYSET, 2.2.7.1.5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PointerCapabilitySet {
    /// `colorPointerFlag` (MUST be 1 from clients).
    pub color_pointer_flag: u16,
    /// `colorPointerCacheSize`.
    pub color_pointer_cache_size: u16,
    /// `pointerCacheSize` (optional trailing field; 0 when absent).
    pub pointer_cache_size: u16,
}

impl PointerCapabilitySet {
    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.color_pointer_flag.to_le_bytes());
        out.extend_from_slice(&self.color_pointer_cache_size.to_le_bytes());
        out.extend_from_slice(&self.pointer_cache_size.to_le_bytes());
    }

    fn decode_body(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let color_pointer_flag = cur.read_u16_le()?;
        let color_pointer_cache_size = cur.read_u16_le()?;
        let pointer_cache_size = cur.read_u16_le().unwrap_or(0);
        Ok(Self {
            color_pointer_flag,
            color_pointer_cache_size,
            pointer_cache_size,
        })
    }
}

/// Input Capability Set (TS_INPUT_CAPABILITYSET, 2.2.7.1.6). The keyboard fields repeat the
/// GCC Client Core Data values — the default builder copies them from there so the two never
/// disagree.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InputCapabilitySet {
    /// `inputFlags` (`INPUT_FLAG_*` bits).
    pub input_flags: u16,
    /// `keyboardLayout` (mirrors GCC core data).
    pub keyboard_layout: u32,
    /// `keyboardType` (mirrors GCC core data).
    pub keyboard_type: u32,
    /// `keyboardSubType` (mirrors GCC core data).
    pub keyboard_subtype: u32,
    /// `keyboardFunctionKey` (mirrors GCC core data).
    pub keyboard_function_key: u32,
}

impl InputCapabilitySet {
    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.input_flags.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // pad2octetsA
        out.extend_from_slice(&self.keyboard_layout.to_le_bytes());
        out.extend_from_slice(&self.keyboard_type.to_le_bytes());
        out.extend_from_slice(&self.keyboard_subtype.to_le_bytes());
        out.extend_from_slice(&self.keyboard_function_key.to_le_bytes());
        out.extend_from_slice(&[0u8; 64]); // imeFileName (zeroed; IME epic is backlog)
    }

    fn decode_body(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let input_flags = cur.read_u16_le()?;
        cur.read_u16_le()?; // pad2octetsA
        let keyboard_layout = cur.read_u32_le()?;
        let keyboard_type = cur.read_u32_le()?;
        let keyboard_subtype = cur.read_u32_le()?;
        let keyboard_function_key = cur.read_u32_le()?;
        // imeFileName (64 bytes) may be truncated; not consumed.
        Ok(Self {
            input_flags,
            keyboard_layout,
            keyboard_type,
            keyboard_subtype,
            keyboard_function_key,
        })
    }
}

/// Virtual Channel Capability Set (TS_VIRTUALCHANNEL_CAPABILITYSET, 2.2.7.1.10).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VirtualChannelCapabilitySet {
    /// `flags` — compression support (0 = none).
    pub flags: u32,
    /// `VCChunkSize` — optional; 0 when absent.
    pub chunk_size: u32,
}

impl VirtualChannelCapabilitySet {
    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.chunk_size.to_le_bytes());
    }

    fn decode_body(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let flags = cur.read_u32_le()?;
        let chunk_size = cur.read_u32_le().unwrap_or(0);
        Ok(Self { flags, chunk_size })
    }
}

/// One codec entry in the Bitmap Codecs Capability Set (TS_BITMAPCODEC, 2.2.7.2.10.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapCodec {
    /// `codecGUID` (16 bytes, e.g. RemoteFX / NSCodec).
    pub guid: [u8; 16],
    /// `codecID` — the per-session ID the server will reference.
    pub id: u8,
    /// `codecProperties` — codec-specific blob, kept raw (decoded at the codec epics).
    pub properties: Vec<u8>,
}

/// Bitmap Codecs Capability Set (TS_BITMAPCODECS_CAPABILITYSET, 2.2.7.2.10).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BitmapCodecsCapabilitySet {
    /// The advertised codecs.
    pub codecs: Vec<BitmapCodec>,
}

impl BitmapCodecsCapabilitySet {
    fn encode_body(&self, out: &mut Vec<u8>) {
        out.push(self.codecs.len() as u8);
        for codec in &self.codecs {
            out.extend_from_slice(&codec.guid);
            out.push(codec.id);
            out.extend_from_slice(&(codec.properties.len() as u16).to_le_bytes());
            out.extend_from_slice(&codec.properties);
        }
    }

    fn decode_body(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let count = cur.read_u8()? as usize;
        let mut codecs = Vec::with_capacity(count);
        for _ in 0..count {
            let mut guid = [0u8; 16];
            guid.copy_from_slice(cur.read_slice(16)?);
            let id = cur.read_u8()?;
            let len = cur.read_u16_le()? as usize;
            codecs.push(BitmapCodec {
                guid,
                id,
                properties: cur.read_slice(len)?.to_vec(),
            });
        }
        Ok(Self { codecs })
    }
}

/// One capability set: typed where the connect sequence consumes the fields, raw otherwise.
/// Unknown sets are preserved verbatim so a caller-supplied Confirm Active list can carry any
/// set this crate has no struct for yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilitySet {
    /// TS_GENERAL_CAPABILITYSET.
    General(GeneralCapabilitySet),
    /// TS_BITMAP_CAPABILITYSET.
    Bitmap(BitmapCapabilitySet),
    /// TS_ORDER_CAPABILITYSET.
    Order(OrderCapabilitySet),
    /// TS_POINTER_CAPABILITYSET.
    Pointer(PointerCapabilitySet),
    /// TS_INPUT_CAPABILITYSET.
    Input(InputCapabilitySet),
    /// TS_VIRTUALCHANNEL_CAPABILITYSET.
    VirtualChannel(VirtualChannelCapabilitySet),
    /// TS_BITMAPCODECS_CAPABILITYSET.
    BitmapCodecs(BitmapCodecsCapabilitySet),
    /// Any other set, kept as raw body bytes under its `capabilitySetType`.
    Unknown {
        /// `capabilitySetType`.
        set_type: u16,
        /// The body bytes (without the 4-byte set header).
        data: Vec<u8>,
    },
}

impl CapabilitySet {
    /// Encode this set including its 4-byte header.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        let set_type = match self {
            CapabilitySet::General(c) => {
                c.encode_body(&mut body);
                CAPSET_GENERAL
            }
            CapabilitySet::Bitmap(c) => {
                c.encode_body(&mut body);
                CAPSET_BITMAP
            }
            CapabilitySet::Order(c) => {
                c.encode_body(&mut body);
                CAPSET_ORDER
            }
            CapabilitySet::Pointer(c) => {
                c.encode_body(&mut body);
                CAPSET_POINTER
            }
            CapabilitySet::Input(c) => {
                c.encode_body(&mut body);
                CAPSET_INPUT
            }
            CapabilitySet::VirtualChannel(c) => {
                c.encode_body(&mut body);
                CAPSET_VIRTUAL_CHANNEL
            }
            CapabilitySet::BitmapCodecs(c) => {
                c.encode_body(&mut body);
                CAPSET_BITMAP_CODECS
            }
            CapabilitySet::Unknown { set_type, data } => {
                body.extend_from_slice(data);
                *set_type
            }
        };
        out.extend_from_slice(&set_type.to_le_bytes());
        out.extend_from_slice(&((body.len() + 4) as u16).to_le_bytes());
        out.extend_from_slice(&body);
    }

    /// Decode one set (header + body). The body is decoded from its own bounded cursor so a
    /// set lying about its length cannot bleed into its neighbors.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let set_type = cur.read_u16_le()?;
        let length = cur.read_u16_le()? as usize;
        if length < 4 {
            return Err(DecodeError::InvalidField {
                field: "lengthCapability",
                reason: "capability set length must include its 4-byte header",
            });
        }
        let body = cur.read_slice(length - 4)?;
        let mut body_cur = ReadCursor::new(body, "capability set body");
        Ok(match set_type {
            CAPSET_GENERAL => CapabilitySet::General(GeneralCapabilitySet::decode_body(&mut body_cur)?),
            CAPSET_BITMAP => CapabilitySet::Bitmap(BitmapCapabilitySet::decode_body(&mut body_cur)?),
            CAPSET_ORDER => CapabilitySet::Order(OrderCapabilitySet::decode_body(&mut body_cur)?),
            CAPSET_POINTER => CapabilitySet::Pointer(PointerCapabilitySet::decode_body(&mut body_cur)?),
            CAPSET_INPUT => CapabilitySet::Input(InputCapabilitySet::decode_body(&mut body_cur)?),
            CAPSET_VIRTUAL_CHANNEL => {
                CapabilitySet::VirtualChannel(VirtualChannelCapabilitySet::decode_body(&mut body_cur)?)
            }
            CAPSET_BITMAP_CODECS => {
                CapabilitySet::BitmapCodecs(BitmapCodecsCapabilitySet::decode_body(&mut body_cur)?)
            }
            _ => CapabilitySet::Unknown {
                set_type,
                data: body.to_vec(),
            },
        })
    }
}

/// A decoded Demand Active body (TS_DEMAND_ACTIVE_PDU after the share control header; the
/// `shareID` lives in [`crate::share::ShareControlHeader`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemandActive {
    /// `sourceDescriptor` bytes (informational; "RDP" from Windows servers).
    pub source_descriptor: Vec<u8>,
    /// The server's capability sets.
    pub capability_sets: Vec<CapabilitySet>,
}

impl DemandActive {
    /// Decode the body. The trailing `sessionId` is consumed when present (it is ignored by
    /// clients per MS-RDPBCGR).
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let source_len = cur.read_u16_le()? as usize;
        cur.read_u16_le()?; // lengthCombinedCapabilities (recomputed from the count below)
        let source_descriptor = cur.read_slice(source_len)?.to_vec();
        let count = cur.read_u16_le()? as usize;
        cur.read_u16_le()?; // pad2octets
        if count > 64 {
            return Err(DecodeError::InvalidField {
                field: "numberCapabilities",
                reason: "implausible capability set count (cap 64)",
            });
        }
        let mut capability_sets = Vec::with_capacity(count);
        for _ in 0..count {
            capability_sets.push(CapabilitySet::decode(cur)?);
        }
        if cur.remaining() >= 4 {
            cur.read_u32_le()?; // sessionId (ignored)
        }
        Ok(Self {
            source_descriptor,
            capability_sets,
        })
    }

    /// Find the server's Bitmap set — the carrier of the negotiated desktop size.
    pub fn bitmap(&self) -> Option<&BitmapCapabilitySet> {
        self.capability_sets.iter().find_map(|c| match c {
            CapabilitySet::Bitmap(b) => Some(b),
            _ => None,
        })
    }
}

/// Encode a Confirm Active body (TS_CONFIRM_ACTIVE_PDU after the share control header).
/// `originator_id` echoes the server's `PDUSource` (what mstsc does; the spec's fixed
/// `0x03EA` is the same value in practice since the server is always MCS user 1002).
pub fn encode_confirm_active(
    originator_id: u16,
    source_descriptor: &[u8],
    capability_sets: &[CapabilitySet],
) -> Vec<u8> {
    let mut caps = Vec::new();
    for set in capability_sets {
        set.encode(&mut caps);
    }
    let combined = caps.len() + 4; // + numberCapabilities + pad2octets
    let mut out = Vec::new();
    out.extend_from_slice(&originator_id.to_le_bytes());
    out.extend_from_slice(&(source_descriptor.len() as u16).to_le_bytes());
    out.extend_from_slice(&(combined as u16).to_le_bytes());
    out.extend_from_slice(source_descriptor);
    out.extend_from_slice(&(capability_sets.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // pad2octets
    out.extend_from_slice(&caps);
    out
}

/// The client capability sets this library can actually honor today: no drawing orders, no
/// bitmap caches, no glyph support — the server falls back to plain bitmap updates, which is
/// what the rendering slices implement first (ADR-0003 phased codecs). Keyboard and desktop
/// values are copied from the GCC core data so the two advertisements never disagree.
///
/// This is a **default**, not a policy: the caller owns `ConnectConfig::capabilities` and may
/// replace or edit any entry (the same anti-hardcode contract as `earlyCapabilityFlags`,
/// plan.md §0).
pub fn default_client_capabilities(core: &crate::gcc::ClientCoreData) -> Vec<CapabilitySet> {
    vec![
        CapabilitySet::General(GeneralCapabilitySet {
            os_major_type: 1, // OSMAJORTYPE_WINDOWS
            os_minor_type: 3, // OSMINORTYPE_WINDOWS_NT
            // FASTPATH_OUTPUT is load-bearing: modern Windows servers send graphics almost
            // exclusively as fast-path updates and paint *nothing* for a client that does
            // not advertise it (verified against the test VM — only logon notifications
            // arrive, zero bitmap data).
            extra_flags: GENERAL_FASTPATH_OUTPUT_SUPPORTED
                | GENERAL_LONG_CREDENTIALS_SUPPORTED
                | GENERAL_NO_BITMAP_COMPRESSION_HDR,
            refresh_rect_support: 0,
            suppress_output_support: 0,
        }),
        CapabilitySet::Bitmap(BitmapCapabilitySet {
            preferred_bits_per_pixel: core.high_color_depth,
            desktop_width: core.desktop_width,
            desktop_height: core.desktop_height,
            desktop_resize_flag: 1,
            drawing_flags: 0,
        }),
        CapabilitySet::Order(OrderCapabilitySet::default()),
        // Bitmap Cache rev. 1, all caches empty: mandatory in Confirm Active, but unused
        // because order_support above never advertises MEMBLT.
        CapabilitySet::Unknown {
            set_type: CAPSET_BITMAP_CACHE,
            data: vec![0; 36],
        },
        CapabilitySet::Pointer(PointerCapabilitySet {
            color_pointer_flag: 1,
            color_pointer_cache_size: 20,
            pointer_cache_size: 20,
        }),
        // MOUSEX and MOUSE_HWHEEL are advertised because the input encoder handles both
        // (extended buttons; the horizontal wheel folds into pointerFlags exactly like the
        // vertical one) — "advertise everything we can actually handle" (plan.md §1).
        // FASTPATH_INPUT/2 are deliberately absent — those are *server* flags the client
        // reads from Demand Active to pick its input transport.
        CapabilitySet::Input(InputCapabilitySet {
            input_flags: INPUT_FLAG_SCANCODES
                | INPUT_FLAG_MOUSEX
                | INPUT_FLAG_UNICODE
                | INPUT_FLAG_MOUSE_HWHEEL,
            keyboard_layout: core.keyboard_layout,
            keyboard_type: core.keyboard_type,
            keyboard_subtype: core.keyboard_subtype,
            keyboard_function_key: core.keyboard_functional_keys_count,
        }),
        // Brush: BRUSH_DEFAULT (color brushes handled server-side).
        CapabilitySet::Unknown {
            set_type: CAPSET_BRUSH,
            data: vec![0; 4],
        },
        // Glyph cache: 10 cache slots + frag cache zeroed, glyphSupportLevel GLYPH_SUPPORT_NONE.
        CapabilitySet::Unknown {
            set_type: CAPSET_GLYPH_CACHE,
            data: vec![0; 48],
        },
        // Offscreen bitmap cache: unsupported.
        CapabilitySet::Unknown {
            set_type: CAPSET_OFFSCREEN_CACHE,
            data: vec![0; 8],
        },
        CapabilitySet::VirtualChannel(VirtualChannelCapabilitySet {
            flags: 0,          // VCCAPS_NO_COMPR
            chunk_size: 1600,  // CHANNEL_CHUNK_LENGTH
        }),
        // Sound: SOUND_BEEPS_FLAG.
        CapabilitySet::Unknown {
            set_type: CAPSET_SOUND,
            data: vec![1, 0, 0, 0],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_core() -> crate::gcc::ClientCoreData {
        crate::gcc::ClientCoreData {
            version: 0x0008_0004,
            desktop_width: 1280,
            desktop_height: 800,
            keyboard_layout: 0x412,
            client_build: 1,
            client_name: "t".into(),
            keyboard_type: 4,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            ime_file_name: String::new(),
            post_beta2_color_depth: 0xCA01,
            client_product_id: 1,
            serial_number: 0,
            high_color_depth: 24,
            supported_color_depths: 0x0007,
            early_capability_flags: crate::gcc::ClientEarlyCapabilityFlags::empty(),
            dig_product_id: String::new(),
            connection_type: 0,
            server_selected_protocol: crate::nego::SecurityProtocol::from_bits(0),
        }
    }

    #[test]
    fn typed_sets_round_trip() {
        let sets = default_client_capabilities(&sample_core());
        let mut encoded = Vec::new();
        for s in &sets {
            s.encode(&mut encoded);
        }
        let mut cur = ReadCursor::new(&encoded, "test");
        let mut decoded = Vec::new();
        while cur.remaining() > 0 {
            decoded.push(CapabilitySet::decode(&mut cur).unwrap());
        }
        assert_eq!(decoded.len(), sets.len());
        // Typed sets survive the round trip exactly.
        assert_eq!(decoded[0], sets[0]);
        assert_eq!(decoded[1], sets[1]);
        assert_eq!(decoded[2], sets[2]);
        match (&decoded[1], &sets[1]) {
            (CapabilitySet::Bitmap(d), CapabilitySet::Bitmap(_)) => {
                assert_eq!((d.desktop_width, d.desktop_height), (1280, 800));
                assert_eq!(d.preferred_bits_per_pixel, 24);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn default_input_capset_advertises_every_handled_input_feature() {
        // "Advertise everything we can actually handle" (plan.md §1, gate #7): the encoder
        // supports scancodes, MouseX, Unicode, and the horizontal wheel — every one must be
        // advertised, and the fast-path flags must NOT be (those are server-side).
        let sets = default_client_capabilities(&sample_core());
        let input = sets
            .iter()
            .find_map(|s| match s {
                CapabilitySet::Input(i) => Some(i),
                _ => None,
            })
            .expect("defaults include an Input capset");
        for (flag, name) in [
            (INPUT_FLAG_SCANCODES, "SCANCODES"),
            (INPUT_FLAG_MOUSEX, "MOUSEX"),
            (INPUT_FLAG_UNICODE, "UNICODE"),
            (INPUT_FLAG_MOUSE_HWHEEL, "MOUSE_HWHEEL"),
        ] {
            assert!(input.input_flags & flag != 0, "{name} must be advertised");
        }
        for (flag, name) in [
            (INPUT_FLAG_FASTPATH_INPUT, "FASTPATH_INPUT"),
            (INPUT_FLAG_FASTPATH_INPUT2, "FASTPATH_INPUT2"),
        ] {
            assert!(input.input_flags & flag == 0, "{name} is a server flag");
        }
    }

    #[test]
    fn general_capset_pins_wire_layout() {
        let mut out = Vec::new();
        CapabilitySet::General(GeneralCapabilitySet {
            os_major_type: 1,
            os_minor_type: 3,
            extra_flags: 0x0404,
            refresh_rect_support: 1,
            suppress_output_support: 1,
        })
        .encode(&mut out);
        assert_eq!(out.len(), 24);
        assert_eq!(&out[0..2], &CAPSET_GENERAL.to_le_bytes());
        assert_eq!(&out[2..4], &24u16.to_le_bytes());
        assert_eq!(&out[4..6], &1u16.to_le_bytes()); // osMajorType
        assert_eq!(&out[8..10], &0x0200u16.to_le_bytes()); // protocolVersion
        assert_eq!(&out[14..16], &0x0404u16.to_le_bytes()); // extraFlags at offset 14
        assert_eq!(&out[22..24], &[1, 1]); // refreshRect + suppressOutput
    }

    #[test]
    fn demand_active_decodes_and_finds_bitmap() {
        let sets = vec![
            CapabilitySet::General(GeneralCapabilitySet::default()),
            CapabilitySet::Bitmap(BitmapCapabilitySet {
                preferred_bits_per_pixel: 32,
                desktop_width: 1920,
                desktop_height: 1080,
                desktop_resize_flag: 1,
                drawing_flags: 2,
            }),
            CapabilitySet::Unknown {
                set_type: 0x001E,
                data: vec![0xAA; 3],
            },
        ];
        let mut caps = Vec::new();
        for s in &sets {
            s.encode(&mut caps);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_le_bytes()); // lengthSourceDescriptor
        body.extend_from_slice(&((caps.len() + 4) as u16).to_le_bytes());
        body.extend_from_slice(b"RDP\0");
        body.extend_from_slice(&(sets.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&caps);
        body.extend_from_slice(&0u32.to_le_bytes()); // sessionId

        let mut cur = ReadCursor::new(&body, "test");
        let demand = DemandActive::decode(&mut cur).unwrap();
        assert_eq!(cur.remaining(), 0);
        assert_eq!(demand.source_descriptor, b"RDP\0");
        assert_eq!(demand.capability_sets, sets);
        let bitmap = demand.bitmap().unwrap();
        assert_eq!(
            (bitmap.desktop_width, bitmap.desktop_height),
            (1920, 1080)
        );
    }

    #[test]
    fn confirm_active_pins_wire_layout() {
        let sets = vec![CapabilitySet::Unknown {
            set_type: 0x0042,
            data: vec![1, 2, 3],
        }];
        let body = encode_confirm_active(1002, b"justrdp\0", &sets);
        assert_eq!(&body[0..2], &1002u16.to_le_bytes()); // originatorId
        assert_eq!(&body[2..4], &8u16.to_le_bytes()); // lengthSourceDescriptor
        // lengthCombinedCapabilities = sets (7) + count/pad (4).
        assert_eq!(&body[4..6], &11u16.to_le_bytes());
        assert_eq!(&body[6..14], b"justrdp\0");
        assert_eq!(&body[14..16], &1u16.to_le_bytes()); // numberCapabilities
        assert_eq!(&body[16..18], &[0, 0]);
        assert_eq!(&body[18..20], &0x0042u16.to_le_bytes());
        assert_eq!(&body[20..22], &7u16.to_le_bytes());
        assert_eq!(&body[22..25], &[1, 2, 3]);
    }

    #[test]
    fn malformed_capset_length_is_an_error_not_a_panic() {
        // lengthCapability = 2 (< 4) must be rejected.
        let bytes = [0x01, 0x00, 0x02, 0x00];
        let mut cur = ReadCursor::new(&bytes, "test");
        assert!(matches!(
            CapabilitySet::decode(&mut cur),
            Err(DecodeError::InvalidField { .. })
        ));
    }
}
