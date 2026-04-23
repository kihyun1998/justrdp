#![forbid(unsafe_code)]

//! Surface Command PDUs -- MS-RDPBCGR 2.2.9.2 and 2.2.9.1.2.1.10.
//!
//! Surface Commands are carried as the `updateData` payload of a
//! fast-path update with `updateCode = FASTPATH_UPDATETYPE_SURFCMDS (0x4)`.
//! The payload is a raw concatenation of `TS_SURFCMD` structures with no
//! count prefix; the receiver parses until the update's `size` field is
//! exhausted (MS-RDPBCGR 2.2.9.1.2.1.10).
//!
//! This module implements the three currently-defined command types:
//!
//! - `TS_SURFCMD_SET_SURF_BITS` (cmdType `0x0001`, MS-RDPBCGR 2.2.9.2.1)
//! - `TS_SURFCMD_STREAM_SURF_BITS` (cmdType `0x0006`, MS-RDPBCGR 2.2.9.2.2)
//! - `TS_FRAME_MARKER` (cmdType `0x0004`, MS-RDPBCGR 2.2.9.2.3)
//!
//! Plus the `TS_BITMAP_DATA_EX` payload container
//! (MS-RDPBCGR 2.2.9.2.1.1) and its optional
//! `TS_COMPRESSED_BITMAP_HEADER_EX` (MS-RDPBCGR 2.2.9.2.1.1.1).
//!
//! **Server-side usage note**: Windows clients at RDP 10.12+ no longer
//! advertise `SURFCMDS_STREAMSURFACEBITS`, so production servers SHOULD
//! emit `SetSurfaceBits` only. `StreamSurfaceBits` is implemented
//! symmetrically for roundtrip tests and proxy / interop scenarios.

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

// ── Constants ──

/// `CMDTYPE_SET_SURFACE_BITS`. MS-RDPBCGR 2.2.9.1.2.1.10.1.
pub const CMDTYPE_SET_SURFACE_BITS: u16 = 0x0001;

/// `CMDTYPE_FRAME_MARKER`. MS-RDPBCGR 2.2.9.1.2.1.10.1.
pub const CMDTYPE_FRAME_MARKER: u16 = 0x0004;

/// `CMDTYPE_STREAM_SURFACE_BITS`. MS-RDPBCGR 2.2.9.1.2.1.10.1.
pub const CMDTYPE_STREAM_SURFACE_BITS: u16 = 0x0006;

/// `SURFACECMD_FRAMEACTION_BEGIN`. MS-RDPBCGR 2.2.9.2.3.
pub const SURFACECMD_FRAMEACTION_BEGIN: u16 = 0x0000;

/// `SURFACECMD_FRAMEACTION_END`. MS-RDPBCGR 2.2.9.2.3.
pub const SURFACECMD_FRAMEACTION_END: u16 = 0x0001;

/// `EX_COMPRESSED_BITMAP_HEADER_PRESENT` bit in `TS_BITMAP_DATA_EX.flags`.
/// MS-RDPBCGR 2.2.9.2.1.1.
pub const EX_COMPRESSED_BITMAP_HEADER_PRESENT: u8 = 0x01;

/// Fixed wire size of `TS_COMPRESSED_BITMAP_HEADER_EX`. MS-RDPBCGR 2.2.9.2.1.1.1.
pub const TS_COMPRESSED_BITMAP_HEADER_EX_SIZE: usize = 24;

/// Fixed prefix size of `TS_BITMAP_DATA_EX` (everything before the optional
/// `exBitmapDataHeader` and the variable `bitmapData`). MS-RDPBCGR 2.2.9.2.1.1.
pub const TS_BITMAP_DATA_EX_FIXED_SIZE: usize = 12;

/// Fixed prefix size of `TS_SURFCMD_SET_SURF_BITS` / `TS_SURFCMD_STREAM_SURF_BITS`
/// (cmdType + destLeft + destTop + destRight + destBottom, before the
/// `TS_BITMAP_DATA_EX` payload). MS-RDPBCGR 2.2.9.2.1 / 2.2.9.2.2.
pub const TS_SURFCMD_SURF_BITS_HEADER_SIZE: usize = 10;

/// Wire size of `TS_FRAME_MARKER` (cmdType + frameAction + frameId).
/// MS-RDPBCGR 2.2.9.2.3.
pub const TS_FRAME_MARKER_SIZE: usize = 8;

// ── TS_COMPRESSED_BITMAP_HEADER_EX ──

/// Optional extended header inside `TS_BITMAP_DATA_EX`.
/// MS-RDPBCGR 2.2.9.2.1.1.1.
///
/// Present iff the enclosing `TS_BITMAP_DATA_EX::flags` has
/// `EX_COMPRESSED_BITMAP_HEADER_PRESENT (0x01)` set. Carries a 64-bit
/// unique bitmap identifier (`high/lowUniqueId`) and a timestamp
/// (`tmSeconds` / `tmMilliseconds`) used by the client to cache decoded
/// frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompressedBitmapHeaderEx {
    pub high_unique_id: u32,
    pub low_unique_id: u32,
    pub tm_milliseconds: u64,
    pub tm_seconds: u64,
}

impl Encode for CompressedBitmapHeaderEx {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.high_unique_id, "CompressedBitmapHeaderEx::highUniqueId")?;
        dst.write_u32_le(self.low_unique_id, "CompressedBitmapHeaderEx::lowUniqueId")?;
        dst.write_u64_le(self.tm_milliseconds, "CompressedBitmapHeaderEx::tmMilliseconds")?;
        dst.write_u64_le(self.tm_seconds, "CompressedBitmapHeaderEx::tmSeconds")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CompressedBitmapHeaderEx"
    }

    fn size(&self) -> usize {
        TS_COMPRESSED_BITMAP_HEADER_EX_SIZE
    }
}

impl<'de> Decode<'de> for CompressedBitmapHeaderEx {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            high_unique_id: src.read_u32_le("CompressedBitmapHeaderEx::highUniqueId")?,
            low_unique_id: src.read_u32_le("CompressedBitmapHeaderEx::lowUniqueId")?,
            tm_milliseconds: src.read_u64_le("CompressedBitmapHeaderEx::tmMilliseconds")?,
            tm_seconds: src.read_u64_le("CompressedBitmapHeaderEx::tmSeconds")?,
        })
    }
}

// ── TS_BITMAP_DATA_EX ──

/// Extended bitmap data payload. MS-RDPBCGR 2.2.9.2.1.1.
///
/// Carried inside `Set`/`StreamSurfaceBitsCmd`. The `bitmap_data.len()`
/// is encoded on the wire as the `bitmapDataLength` (u32 LE) field, so
/// callers MUST keep this struct invariant:
///
/// - `bitmap_data.len() <= u32::MAX as usize`
/// - `ex_header.is_some()` iff the resulting `flags` byte has
///   `EX_COMPRESSED_BITMAP_HEADER_PRESENT` set.
///
/// The `flags` field is computed at encode time from `ex_header`
/// presence; callers do not set it manually.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapDataEx {
    /// `bpp` -- bits per pixel of the decoded image. Valid values depend
    /// on the codec (uncompressed: 8/15/16/24/32). Not validated at
    /// this layer.
    pub bpp: u8,
    /// Client-assigned codec ID. `0x00` = uncompressed.
    pub codec_id: u8,
    /// Decoded image width in pixels. Authoritative over the
    /// enclosing command's `destRight` field.
    pub width: u16,
    /// Decoded image height in pixels. Authoritative over the
    /// enclosing command's `destBottom` field.
    pub height: u16,
    /// Optional extended header (MS-RDPBCGR 2.2.9.2.1.1.1). Setting
    /// this to `Some(_)` causes `EX_COMPRESSED_BITMAP_HEADER_PRESENT`
    /// to be written in the `flags` byte on encode.
    pub ex_header: Option<CompressedBitmapHeaderEx>,
    /// Raw encoded or uncompressed pixel bytes. Length becomes the
    /// wire `bitmapDataLength` u32 field.
    pub bitmap_data: Vec<u8>,
}

impl Encode for BitmapDataEx {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // Guard the u32-on-wire cast BEFORE writing any byte so a failure
        // leaves the cursor position unchanged.
        if self.bitmap_data.len() > u32::MAX as usize {
            return Err(EncodeError::other(
                "BitmapDataEx",
                "bitmapData length exceeds u32::MAX",
            ));
        }
        let flags = if self.ex_header.is_some() {
            EX_COMPRESSED_BITMAP_HEADER_PRESENT
        } else {
            0
        };
        dst.write_u8(self.bpp, "BitmapDataEx::bpp")?;
        dst.write_u8(flags, "BitmapDataEx::flags")?;
        dst.write_u8(0, "BitmapDataEx::reserved")?;
        dst.write_u8(self.codec_id, "BitmapDataEx::codecID")?;
        dst.write_u16_le(self.width, "BitmapDataEx::width")?;
        dst.write_u16_le(self.height, "BitmapDataEx::height")?;
        dst.write_u32_le(
            self.bitmap_data.len() as u32,
            "BitmapDataEx::bitmapDataLength",
        )?;
        if let Some(ref ex) = self.ex_header {
            ex.encode(dst)?;
        }
        dst.write_slice(&self.bitmap_data, "BitmapDataEx::bitmapData")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "BitmapDataEx"
    }

    fn size(&self) -> usize {
        TS_BITMAP_DATA_EX_FIXED_SIZE
            + self.ex_header.map_or(0, |_| TS_COMPRESSED_BITMAP_HEADER_EX_SIZE)
            + self.bitmap_data.len()
    }
}

impl<'de> Decode<'de> for BitmapDataEx {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let bpp = src.read_u8("BitmapDataEx::bpp")?;
        let flags = src.read_u8("BitmapDataEx::flags")?;
        // `reserved` byte: spec mandates 0 on encode but says nothing about
        // decode. Accept any value to stay forward-compatible with future
        // flag allocations.
        let _reserved = src.read_u8("BitmapDataEx::reserved")?;
        let codec_id = src.read_u8("BitmapDataEx::codecID")?;
        let width = src.read_u16_le("BitmapDataEx::width")?;
        let height = src.read_u16_le("BitmapDataEx::height")?;
        let bitmap_data_length = src.read_u32_le("BitmapDataEx::bitmapDataLength")?;
        let ex_header = if flags & EX_COMPRESSED_BITMAP_HEADER_PRESENT != 0 {
            Some(CompressedBitmapHeaderEx::decode(src)?)
        } else {
            None
        };
        let bitmap_data = src
            .read_slice(
                bitmap_data_length as usize,
                "BitmapDataEx::bitmapData",
            )?
            .to_vec();
        Ok(Self {
            bpp,
            codec_id,
            width,
            height,
            ex_header,
            bitmap_data,
        })
    }
}

// ── TS_SURFCMD_SET_SURF_BITS ──

/// Set Surface Bits command. MS-RDPBCGR 2.2.9.2.1.
///
/// `dest_right` / `dest_bottom` are **exclusive** upper bounds on the
/// wire (unlike the inclusive bounds in `TS_BITMAP_DATA`). Per spec
/// Remarks the receiver SHOULD ignore them and use
/// `bitmap_data.width` / `bitmap_data.height` instead; we still write
/// them faithfully for receivers that use them as a fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetSurfaceBitsCmd {
    pub dest_left: u16,
    pub dest_top: u16,
    pub dest_right: u16,
    pub dest_bottom: u16,
    pub bitmap_data: BitmapDataEx,
}

impl Encode for SetSurfaceBitsCmd {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(CMDTYPE_SET_SURFACE_BITS, "SetSurfaceBitsCmd::cmdType")?;
        dst.write_u16_le(self.dest_left, "SetSurfaceBitsCmd::destLeft")?;
        dst.write_u16_le(self.dest_top, "SetSurfaceBitsCmd::destTop")?;
        dst.write_u16_le(self.dest_right, "SetSurfaceBitsCmd::destRight")?;
        dst.write_u16_le(self.dest_bottom, "SetSurfaceBitsCmd::destBottom")?;
        self.bitmap_data.encode(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SetSurfaceBitsCmd"
    }

    fn size(&self) -> usize {
        TS_SURFCMD_SURF_BITS_HEADER_SIZE + self.bitmap_data.size()
    }
}

impl<'de> Decode<'de> for SetSurfaceBitsCmd {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cmd_type = src.read_u16_le("SetSurfaceBitsCmd::cmdType")?;
        if cmd_type != CMDTYPE_SET_SURFACE_BITS {
            return Err(DecodeError::unexpected_value(
                "SetSurfaceBitsCmd",
                "cmdType",
                "expected CMDTYPE_SET_SURFACE_BITS (0x0001)",
            ));
        }
        decode_surf_bits_after_cmd_type(src).map(|(l, t, r, b, data)| Self {
            dest_left: l,
            dest_top: t,
            dest_right: r,
            dest_bottom: b,
            bitmap_data: data,
        })
    }
}

// ── TS_SURFCMD_STREAM_SURF_BITS ──

/// Stream Surface Bits command. MS-RDPBCGR 2.2.9.2.2.
///
/// Identical layout to [`SetSurfaceBitsCmd`] except for the `cmdType`
/// value. Windows clients at RDP 10.12+ no longer advertise support for
/// this command type, so production servers SHOULD NOT emit it. Kept
/// here for roundtrip tests and interop scenarios.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSurfaceBitsCmd {
    pub dest_left: u16,
    pub dest_top: u16,
    pub dest_right: u16,
    pub dest_bottom: u16,
    pub bitmap_data: BitmapDataEx,
}

impl Encode for StreamSurfaceBitsCmd {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(CMDTYPE_STREAM_SURFACE_BITS, "StreamSurfaceBitsCmd::cmdType")?;
        dst.write_u16_le(self.dest_left, "StreamSurfaceBitsCmd::destLeft")?;
        dst.write_u16_le(self.dest_top, "StreamSurfaceBitsCmd::destTop")?;
        dst.write_u16_le(self.dest_right, "StreamSurfaceBitsCmd::destRight")?;
        dst.write_u16_le(self.dest_bottom, "StreamSurfaceBitsCmd::destBottom")?;
        self.bitmap_data.encode(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "StreamSurfaceBitsCmd"
    }

    fn size(&self) -> usize {
        TS_SURFCMD_SURF_BITS_HEADER_SIZE + self.bitmap_data.size()
    }
}

impl<'de> Decode<'de> for StreamSurfaceBitsCmd {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cmd_type = src.read_u16_le("StreamSurfaceBitsCmd::cmdType")?;
        if cmd_type != CMDTYPE_STREAM_SURFACE_BITS {
            return Err(DecodeError::unexpected_value(
                "StreamSurfaceBitsCmd",
                "cmdType",
                "expected CMDTYPE_STREAM_SURFACE_BITS (0x0006)",
            ));
        }
        decode_surf_bits_after_cmd_type(src).map(|(l, t, r, b, data)| Self {
            dest_left: l,
            dest_top: t,
            dest_right: r,
            dest_bottom: b,
            bitmap_data: data,
        })
    }
}

/// Shared decode path for the Set / Stream surface bits commands; both
/// share the identical post-`cmdType` layout.
fn decode_surf_bits_after_cmd_type<'de>(
    src: &mut ReadCursor<'de>,
) -> DecodeResult<(u16, u16, u16, u16, BitmapDataEx)> {
    let dest_left = src.read_u16_le("SurfBitsCmd::destLeft")?;
    let dest_top = src.read_u16_le("SurfBitsCmd::destTop")?;
    let dest_right = src.read_u16_le("SurfBitsCmd::destRight")?;
    let dest_bottom = src.read_u16_le("SurfBitsCmd::destBottom")?;
    let bitmap_data = BitmapDataEx::decode(src)?;
    Ok((dest_left, dest_top, dest_right, dest_bottom, bitmap_data))
}

// ── TS_FRAME_MARKER ──

/// Frame Marker command. MS-RDPBCGR 2.2.9.2.3.
///
/// `frame_action` must be one of [`SURFACECMD_FRAMEACTION_BEGIN`] or
/// [`SURFACECMD_FRAMEACTION_END`]; other values are rejected on decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMarkerCmd {
    pub frame_action: u16,
    pub frame_id: u32,
}

impl FrameMarkerCmd {
    /// Construct a `BEGIN` marker for the given frame id.
    pub fn begin(frame_id: u32) -> Self {
        Self {
            frame_action: SURFACECMD_FRAMEACTION_BEGIN,
            frame_id,
        }
    }

    /// Construct an `END` marker for the given frame id.
    pub fn end(frame_id: u32) -> Self {
        Self {
            frame_action: SURFACECMD_FRAMEACTION_END,
            frame_id,
        }
    }
}

impl Encode for FrameMarkerCmd {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.frame_action != SURFACECMD_FRAMEACTION_BEGIN
            && self.frame_action != SURFACECMD_FRAMEACTION_END
        {
            return Err(EncodeError::invalid_value(
                "FrameMarkerCmd",
                "frameAction",
            ));
        }
        dst.write_u16_le(CMDTYPE_FRAME_MARKER, "FrameMarkerCmd::cmdType")?;
        dst.write_u16_le(self.frame_action, "FrameMarkerCmd::frameAction")?;
        dst.write_u32_le(self.frame_id, "FrameMarkerCmd::frameId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "FrameMarkerCmd"
    }

    fn size(&self) -> usize {
        TS_FRAME_MARKER_SIZE
    }
}

impl<'de> Decode<'de> for FrameMarkerCmd {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cmd_type = src.read_u16_le("FrameMarkerCmd::cmdType")?;
        if cmd_type != CMDTYPE_FRAME_MARKER {
            return Err(DecodeError::unexpected_value(
                "FrameMarkerCmd",
                "cmdType",
                "expected CMDTYPE_FRAME_MARKER (0x0004)",
            ));
        }
        let frame_action = src.read_u16_le("FrameMarkerCmd::frameAction")?;
        if frame_action != SURFACECMD_FRAMEACTION_BEGIN
            && frame_action != SURFACECMD_FRAMEACTION_END
        {
            return Err(DecodeError::unexpected_value(
                "FrameMarkerCmd",
                "frameAction",
                "unknown frame action",
            ));
        }
        let frame_id = src.read_u32_le("FrameMarkerCmd::frameId")?;
        Ok(Self {
            frame_action,
            frame_id,
        })
    }
}

// ── Dispatch enum ──

/// Dispatch enum over the three surface command variants. Used by
/// generic decoders that walk a concatenated stream of `TS_SURFCMD`
/// structures inside a fast-path `SurfaceCommands` update.
///
/// Unknown `cmdType` values cannot be skipped because the length of
/// `cmdData` is not encoded in the container — decoding an unknown
/// variant returns a `DecodeError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceCommand {
    SetSurfaceBits(SetSurfaceBitsCmd),
    StreamSurfaceBits(StreamSurfaceBitsCmd),
    FrameMarker(FrameMarkerCmd),
}

impl Encode for SurfaceCommand {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        match self {
            Self::SetSurfaceBits(c) => c.encode(dst),
            Self::StreamSurfaceBits(c) => c.encode(dst),
            Self::FrameMarker(c) => c.encode(dst),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::SetSurfaceBits(_) => "SurfaceCommand::SetSurfaceBits",
            Self::StreamSurfaceBits(_) => "SurfaceCommand::StreamSurfaceBits",
            Self::FrameMarker(_) => "SurfaceCommand::FrameMarker",
        }
    }

    fn size(&self) -> usize {
        match self {
            Self::SetSurfaceBits(c) => c.size(),
            Self::StreamSurfaceBits(c) => c.size(),
            Self::FrameMarker(c) => c.size(),
        }
    }
}

impl<'de> Decode<'de> for SurfaceCommand {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        // Peek `cmdType` without consuming bytes so each variant's own
        // `decode` can re-read its cmdType and validate it.
        if src.remaining() < 2 {
            return Err(DecodeError::not_enough_bytes(
                "SurfaceCommand::cmdType",
                2,
                src.remaining(),
            ));
        }
        let head = src.peek_remaining();
        let cmd_type = u16::from_le_bytes([head[0], head[1]]);
        match cmd_type {
            CMDTYPE_SET_SURFACE_BITS => Ok(Self::SetSurfaceBits(SetSurfaceBitsCmd::decode(src)?)),
            CMDTYPE_FRAME_MARKER => Ok(Self::FrameMarker(FrameMarkerCmd::decode(src)?)),
            CMDTYPE_STREAM_SURFACE_BITS => {
                Ok(Self::StreamSurfaceBits(StreamSurfaceBitsCmd::decode(src)?))
            }
            _ => Err(DecodeError::unexpected_value(
                "SurfaceCommand",
                "cmdType",
                "unknown surface command type",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn roundtrip<T>(value: &T) -> T
    where
        T: Encode + for<'de> Decode<'de> + core::fmt::Debug + PartialEq,
    {
        let mut buf = vec![0u8; value.size()];
        let mut dst = WriteCursor::new(&mut buf);
        value.encode(&mut dst).expect("encode");
        let written = dst.pos();
        assert_eq!(
            written,
            value.size(),
            "size() must match encode() for {}",
            value.name()
        );
        let mut src = ReadCursor::new(&buf[..written]);
        let decoded = T::decode(&mut src).expect("decode");
        assert_eq!(src.remaining(), 0, "leftover bytes after decode");
        decoded
    }

    #[test]
    fn frame_marker_begin_roundtrip() {
        let m = FrameMarkerCmd::begin(0);
        let d = roundtrip(&m);
        assert_eq!(d, m);
        assert_eq!(m.size(), TS_FRAME_MARKER_SIZE);
    }

    #[test]
    fn frame_marker_end_max_frame_id_roundtrip() {
        let m = FrameMarkerCmd::end(u32::MAX);
        let d = roundtrip(&m);
        assert_eq!(d, m);
    }

    #[test]
    fn frame_marker_encode_rejects_invalid_action() {
        let m = FrameMarkerCmd {
            frame_action: 0x00FF,
            frame_id: 0,
        };
        let mut buf = [0u8; TS_FRAME_MARKER_SIZE];
        let mut dst = WriteCursor::new(&mut buf);
        assert!(m.encode(&mut dst).is_err());
    }

    #[test]
    fn frame_marker_decode_rejects_invalid_action() {
        // cmdType=0x0004, frameAction=0x0002 (invalid), frameId=0.
        let bytes = [0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut src = ReadCursor::new(&bytes);
        assert!(FrameMarkerCmd::decode(&mut src).is_err());
    }

    #[test]
    fn frame_marker_decode_rejects_wrong_cmd_type() {
        // cmdType=0x0001 (SetSurfaceBits, not FrameMarker).
        let bytes = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut src = ReadCursor::new(&bytes);
        assert!(FrameMarkerCmd::decode(&mut src).is_err());
    }

    #[test]
    fn bitmap_data_ex_no_exheader_roundtrip() {
        let data = BitmapDataEx {
            bpp: 32,
            codec_id: 0,
            width: 64,
            height: 64,
            ex_header: None,
            bitmap_data: vec![0xAB; 16_384],
        };
        let d = roundtrip(&data);
        assert_eq!(d, data);
        assert_eq!(data.size(), TS_BITMAP_DATA_EX_FIXED_SIZE + 16_384);
    }

    #[test]
    fn bitmap_data_ex_with_exheader_roundtrip() {
        let data = BitmapDataEx {
            bpp: 32,
            codec_id: 0x03,
            width: 16,
            height: 16,
            ex_header: Some(CompressedBitmapHeaderEx {
                high_unique_id: 0xDEADBEEF,
                low_unique_id: 0xCAFEBABE,
                tm_milliseconds: 123,
                tm_seconds: 456,
            }),
            bitmap_data: vec![0xCD; 32],
        };
        let d = roundtrip(&data);
        assert_eq!(d, data);
        assert_eq!(
            data.size(),
            TS_BITMAP_DATA_EX_FIXED_SIZE + TS_COMPRESSED_BITMAP_HEADER_EX_SIZE + 32,
        );
    }

    #[test]
    fn bitmap_data_ex_zero_length_payload_roundtrip() {
        let data = BitmapDataEx {
            bpp: 32,
            codec_id: 0,
            width: 1,
            height: 1,
            ex_header: None,
            bitmap_data: vec![],
        };
        let d = roundtrip(&data);
        assert_eq!(d, data);
        assert_eq!(data.size(), TS_BITMAP_DATA_EX_FIXED_SIZE);
    }

    #[test]
    fn bitmap_data_ex_encode_sets_flag_iff_exheader_present() {
        let with_ex = BitmapDataEx {
            bpp: 32,
            codec_id: 0,
            width: 1,
            height: 1,
            ex_header: Some(CompressedBitmapHeaderEx::default()),
            bitmap_data: vec![],
        };
        let without_ex = BitmapDataEx {
            bpp: 32,
            codec_id: 0,
            width: 1,
            height: 1,
            ex_header: None,
            bitmap_data: vec![],
        };
        let mut buf = vec![0u8; 64];
        {
            let mut dst = WriteCursor::new(&mut buf);
            with_ex.encode(&mut dst).unwrap();
        }
        assert_eq!(buf[1] & EX_COMPRESSED_BITMAP_HEADER_PRESENT, 0x01);
        buf.fill(0);
        {
            let mut dst = WriteCursor::new(&mut buf);
            without_ex.encode(&mut dst).unwrap();
        }
        assert_eq!(buf[1] & EX_COMPRESSED_BITMAP_HEADER_PRESENT, 0x00);
    }

    #[test]
    fn bitmap_data_ex_decode_accepts_nonzero_reserved_byte() {
        // Spec says reserved MUST be 0 on encode but does not mandate
        // rejection on decode; we stay forward-compatible.
        let bytes = [
            0x20, // bpp=32
            0x00, // flags=0
            0xFF, // reserved (non-zero)
            0x00, // codecID
            0x01, 0x00, // width=1
            0x01, 0x00, // height=1
            0x00, 0x00, 0x00, 0x00, // bitmapDataLength=0
        ];
        let mut src = ReadCursor::new(&bytes);
        let d = BitmapDataEx::decode(&mut src).expect("decode");
        assert_eq!(d.bpp, 32);
        assert_eq!(src.remaining(), 0);
    }

    #[test]
    fn bitmap_data_ex_decode_errors_when_exheader_flag_set_but_truncated() {
        // flags says exHeader present but stream runs out before it can
        // be read.
        let bytes = [
            0x20, // bpp
            EX_COMPRESSED_BITMAP_HEADER_PRESENT, // flags with ex bit
            0x00, // reserved
            0x00, // codecID
            0x01, 0x00, // width
            0x01, 0x00, // height
            0x00, 0x00, 0x00, 0x00, // bitmapDataLength=0
            // exHeader bytes missing
        ];
        let mut src = ReadCursor::new(&bytes);
        assert!(BitmapDataEx::decode(&mut src).is_err());
    }

    fn sample_bitmap_data_ex() -> BitmapDataEx {
        BitmapDataEx {
            bpp: 32,
            codec_id: 0,
            width: 8,
            height: 8,
            ex_header: None,
            bitmap_data: vec![0u8; 8 * 8 * 4],
        }
    }

    #[test]
    fn set_surface_bits_roundtrip() {
        let cmd = SetSurfaceBitsCmd {
            dest_left: 10,
            dest_top: 20,
            dest_right: 18,
            dest_bottom: 28,
            bitmap_data: sample_bitmap_data_ex(),
        };
        let d = roundtrip(&cmd);
        assert_eq!(d, cmd);
        assert_eq!(
            cmd.size(),
            TS_SURFCMD_SURF_BITS_HEADER_SIZE + cmd.bitmap_data.size(),
        );
    }

    #[test]
    fn set_surface_bits_decode_rejects_wrong_cmd_type() {
        // cmdType=0x0006 (StreamSurfaceBits) but we call SetSurfaceBits::decode.
        let cmd = StreamSurfaceBitsCmd {
            dest_left: 0,
            dest_top: 0,
            dest_right: 8,
            dest_bottom: 8,
            bitmap_data: sample_bitmap_data_ex(),
        };
        let mut buf = vec![0u8; cmd.size()];
        let mut dst = WriteCursor::new(&mut buf);
        cmd.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert!(SetSurfaceBitsCmd::decode(&mut src).is_err());
    }

    #[test]
    fn stream_surface_bits_decode_rejects_wrong_cmd_type() {
        // cmdType=0x0001 (SetSurfaceBits) but we call StreamSurfaceBits::decode.
        let cmd = SetSurfaceBitsCmd {
            dest_left: 0,
            dest_top: 0,
            dest_right: 8,
            dest_bottom: 8,
            bitmap_data: sample_bitmap_data_ex(),
        };
        let mut buf = vec![0u8; cmd.size()];
        let mut dst = WriteCursor::new(&mut buf);
        cmd.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert!(StreamSurfaceBitsCmd::decode(&mut src).is_err());
    }

    #[test]
    fn stream_surface_bits_roundtrip() {
        let cmd = StreamSurfaceBitsCmd {
            dest_left: 0,
            dest_top: 0,
            dest_right: 8,
            dest_bottom: 8,
            bitmap_data: sample_bitmap_data_ex(),
        };
        let d = roundtrip(&cmd);
        assert_eq!(d, cmd);
    }

    #[test]
    fn surface_command_dispatch_set_bits() {
        let inner = SetSurfaceBitsCmd {
            dest_left: 0,
            dest_top: 0,
            dest_right: 8,
            dest_bottom: 8,
            bitmap_data: sample_bitmap_data_ex(),
        };
        let cmd = SurfaceCommand::SetSurfaceBits(inner.clone());
        let d = roundtrip(&cmd);
        assert_eq!(d, cmd);
        match d {
            SurfaceCommand::SetSurfaceBits(got) => assert_eq!(got, inner),
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn surface_command_dispatch_stream_bits() {
        let inner = StreamSurfaceBitsCmd {
            dest_left: 0,
            dest_top: 0,
            dest_right: 8,
            dest_bottom: 8,
            bitmap_data: sample_bitmap_data_ex(),
        };
        let cmd = SurfaceCommand::StreamSurfaceBits(inner.clone());
        let d = roundtrip(&cmd);
        assert_eq!(d, cmd);
    }

    #[test]
    fn surface_command_dispatch_frame_marker() {
        let cmd = SurfaceCommand::FrameMarker(FrameMarkerCmd::begin(42));
        let d = roundtrip(&cmd);
        assert_eq!(d, cmd);
    }

    #[test]
    fn surface_command_dispatch_unknown_cmd_type_errors() {
        // cmdType = 0x0002 (undefined) — decoder must not silently skip
        // because the length of cmdData is not self-describing.
        let bytes = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut src = ReadCursor::new(&bytes);
        assert!(SurfaceCommand::decode(&mut src).is_err());
    }

    #[test]
    fn surface_command_dispatch_empty_input_errors() {
        let mut src = ReadCursor::new(&[]);
        assert!(SurfaceCommand::decode(&mut src).is_err());
    }
}
