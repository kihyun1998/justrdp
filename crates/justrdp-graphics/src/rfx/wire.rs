#![forbid(unsafe_code)]

//! RFX wire-level message framing -- MS-RDPRFX 2.2.2.
//!
//! The codec layer (`super::RfxEncoder` / `RfxDecoder`) operates at the
//! tile granularity (one 64×64 BGRA tile in, RLGR-encoded Y/Cb/Cr
//! bitstreams out). This module wraps those bitstreams in the
//! per-message framing the wire format requires.
//!
//! ## Block hierarchy
//!
//! Two header shapes:
//!
//! - [`RfxBlockHeader`] — `TS_RFX_BLOCKT` (MS-RDPRFX 2.2.2.1.1):
//!   `blockType` (u16 LE) + `blockLen` (u32 LE) = **6 bytes**. Used by
//!   `WBT_SYNC`, `WBT_CODEC_VERSIONS`, `WBT_CHANNELS`, and the
//!   per-tile `CBT_TILE` inner blocks.
//! - [`RfxCodecChannelHeader`] — `TS_RFX_CODEC_CHANNELT`
//!   (MS-RDPRFX 2.2.2.1.2): the 6-byte block header followed by
//!   `codecId` (u8) + `channelId` (u8) = **8 bytes**. Used by every
//!   block carrying frame data: `WBT_CONTEXT`, `WBT_FRAME_BEGIN`,
//!   `WBT_FRAME_END`, `WBT_REGION`, `WBT_EXTENSION` (TileSet).
//!
//! `blockLen` always counts from the first byte of the header itself
//! (i.e. it includes the 6 / 8 header bytes).
//!
//! ## Sub-section coverage
//!
//! Staged across §11.2b-2 commits. So far: handshake set (Sync /
//! CodecVersions / Channels) and the codec context (Context, including
//! the [`RfxProperties`] bitfield helper shared with TileSet).
//! Remaining commits add FrameBegin / FrameEnd / Region, TileSet /
//! Tile, and the [`RfxFrameEncoder`] state machine.

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use super::quant::CodecQuant;
use super::rlgr::RlgrMode;

// ── Block type constants (MS-RDPRFX 2.2.2.1.1) ──────────────────────

/// `WBT_SYNC` — first message in any encoded RFX stream.
pub const WBT_SYNC: u16 = 0xCCC0;

/// `WBT_CODEC_VERSIONS` — list of supported codec versions.
pub const WBT_CODEC_VERSIONS: u16 = 0xCCC1;

/// `WBT_CHANNELS` — per-channel monitor dimensions.
pub const WBT_CHANNELS: u16 = 0xCCC2;

/// `WBT_CONTEXT` — codec context (entropy / quant / DWT mode).
pub const WBT_CONTEXT: u16 = 0xCCC3;

/// `WBT_FRAME_BEGIN` — start of a frame's region+tileset payload.
pub const WBT_FRAME_BEGIN: u16 = 0xCCC4;

/// `WBT_FRAME_END` — end-of-frame marker.
pub const WBT_FRAME_END: u16 = 0xCCC5;

/// `WBT_REGION` — destination rectangles for the upcoming TileSet.
pub const WBT_REGION: u16 = 0xCCC6;

/// `WBT_EXTENSION` — TileSet payload (the spec calls this
/// `WBT_EXTENSION`; commonly referred to as `WBT_TILESET` in RFX
/// implementations because the only extension currently defined is the
/// TileSet, distinguished further by the inner `subtype = CBT_TILESET`).
pub const WBT_EXTENSION: u16 = 0xCCC7;

/// `CBT_TILE` — per-tile inner block inside a `WBT_EXTENSION` (TileSet)
/// payload. Uses the plain 6-byte [`RfxBlockHeader`] (no `codecId`/`channelId`).
pub const CBT_TILE: u16 = 0xCAC3;

/// `CBT_REGION` — the `regionType` constant inside `WBT_REGION`.
pub const CBT_REGION: u16 = 0xCAC1;

/// `CBT_TILESET` — the `subtype` constant inside `WBT_EXTENSION`.
pub const CBT_TILESET: u16 = 0xCAC2;

// ── Properties bitfield constants (MS-RDPRFX 2.2.2.2.4 / 2.2.2.3.4) ─

/// `flags = CODEC_MODE` -- image mode (every frame is independently
/// decodable; handshake messages MUST precede each frame).
/// MS-RDPRFX 2.2.2.2.4.
pub const CODEC_MODE_IMAGE: u8 = 0x02;

/// `cct = COL_CONV_ICT` -- the only color-conversion transform
/// currently defined; MUST be written as 0x1. MS-RDPRFX 2.2.2.2.4.
pub const COL_CONV_ICT: u8 = 0x1;

/// `xft = CLW_XFORM_DWT_53_A` -- the only DWT variant currently
/// defined; MUST be written as 0x1. MS-RDPRFX 2.2.2.2.4.
pub const CLW_XFORM_DWT_53_A: u8 = 0x1;

/// `et = CLW_ENTROPY_RLGR1` -- RLGR1 entropy coder.
/// MS-RDPRFX 2.2.2.2.4.
pub const CLW_ENTROPY_RLGR1: u8 = 0x01;

/// `et = CLW_ENTROPY_RLGR3` -- RLGR3 entropy coder.
/// MS-RDPRFX 2.2.2.2.4.
pub const CLW_ENTROPY_RLGR3: u8 = 0x04;

/// `qt = SCALAR_QUANTIZATION` -- the only quantization type currently
/// defined; MUST be written as 0x1. MS-RDPRFX 2.2.2.2.4.
pub const SCALAR_QUANTIZATION: u8 = 0x1;

// ── Magic / version / fixed-value constants ─────────────────────────

/// `WF_MAGIC` — magic value in `TS_RFX_SYNC.magic` (MS-RDPRFX 2.2.2.2.1).
pub const WF_MAGIC: u32 = 0xCACC_ACCA;

/// `WF_VERSION_1_0` — protocol version (MS-RDPRFX 2.2.2.2.1 / 2.2.2.2.2).
pub const WF_VERSION_1_0: u16 = 0x0100;

/// RFX `codecId` — the only currently-defined value
/// (MS-RDPRFX 2.2.2.1.2 / 2.2.2.2.2).
pub const CODEC_ID: u8 = 0x01;

/// `channelId = 0xFF` — the special "all channels" id used **only**
/// in `WBT_CONTEXT` (MS-RDPRFX 2.2.2.1.2).
pub const CHANNEL_ID_CONTEXT: u8 = 0xFF;

/// `channelId = 0x00` — the per-channel id used by every RFX block
/// other than `WBT_CONTEXT` (MS-RDPRFX 2.2.2.1.2). The same value also
/// appears inside each `TS_RFX_CHANNELT` entry (MS-RDPRFX 2.2.2.1.3).
pub const CHANNEL_ID_DATA: u8 = 0x00;

// ── Channel dimension limits (MS-RDPRFX 2.2.2.1.3) ──────────────────

/// Lower bound for `TS_RFX_CHANNELT.width` (MS-RDPRFX 2.2.2.1.3 says
/// width SHOULD be in `1..=4096`; we enforce as a hard error to avoid
/// interop surprises).
pub const RFX_MIN_CHANNEL_WIDTH: i16 = 1;

/// Upper bound for `TS_RFX_CHANNELT.width` (MS-RDPRFX 2.2.2.1.3).
pub const RFX_MAX_CHANNEL_WIDTH: i16 = 4096;

/// Lower bound for `TS_RFX_CHANNELT.height` (MS-RDPRFX 2.2.2.1.3).
pub const RFX_MIN_CHANNEL_HEIGHT: i16 = 1;

/// Upper bound for `TS_RFX_CHANNELT.height` (MS-RDPRFX 2.2.2.1.3).
pub const RFX_MAX_CHANNEL_HEIGHT: i16 = 2048;

// ── Fixed wire sizes ────────────────────────────────────────────────

/// Size of `TS_RFX_BLOCKT` (MS-RDPRFX 2.2.2.1.1).
pub const RFX_BLOCK_HEADER_SIZE: usize = 6;

/// Size of `TS_RFX_CODEC_CHANNELT` (MS-RDPRFX 2.2.2.1.2).
pub const RFX_CODEC_CHANNEL_HEADER_SIZE: usize = 8;

/// Total wire size of a `TS_RFX_SYNC` block (header + magic + version).
pub const RFX_SYNC_SIZE: usize = 12;

/// Total wire size of a `TS_RFX_CODEC_VERSIONS` block (single codec
/// entry, the only currently-defined shape).
pub const RFX_CODEC_VERSIONS_SIZE: usize = 10;

/// Wire size of a single `TS_RFX_CHANNELT` entry inside `WBT_CHANNELS`
/// (MS-RDPRFX 2.2.2.1.3).
pub const RFX_CHANNELT_SIZE: usize = 5;

/// Total wire size of a `TS_RFX_CONTEXT` block (MS-RDPRFX 2.2.2.2.4).
pub const RFX_CONTEXT_SIZE: usize = 13;

/// Fixed `ctxId` value -- MUST be 0 (MS-RDPRFX 2.2.2.2.4).
pub const CTX_ID: u8 = 0x00;

/// `tileSize` value inside `TS_RFX_CONTEXT` -- MUST be `0x0040`
/// (64 pixels). MS-RDPRFX 2.2.2.2.4.
pub const CT_TILE_64X64: u16 = 0x0040;

/// Total wire size of a `TS_RFX_FRAME_BEGIN` block
/// (MS-RDPRFX 2.2.2.3.1).
pub const RFX_FRAME_BEGIN_SIZE: usize = 14;

/// Total wire size of a `TS_RFX_FRAME_END` block
/// (MS-RDPRFX 2.2.2.3.2). Only the 8-byte `TS_RFX_CODEC_CHANNELT`
/// header -- no body.
pub const RFX_FRAME_END_SIZE: usize = 8;

/// `regionFlags` value: bit 0 = `lrf` MUST be `1`; upper 7 bits
/// reserved (write 0). MS-RDPRFX 2.2.2.3.3.
pub const REGION_FLAGS_LRF: u8 = 0x01;

/// `numTilesets` value inside `TS_RFX_REGION` -- MUST be `0x0001`.
/// MS-RDPRFX 2.2.2.3.3.
pub const NUM_TILESETS_MUST: u16 = 0x0001;

/// Wire size of a single `TS_RFX_RECT` entry (MS-RDPRFX 2.2.2.1.4).
pub const RFX_RECT_SIZE: usize = 8;

/// Wire size of a single `CodecQuant` entry inside `WBT_EXTENSION`
/// (MS-RDPRFX 2.2.2.1.5).
pub const RFX_CODEC_QUANT_SIZE: usize = 5;

/// Fixed prefix (header + sub-fields up to and including
/// `tilesDataSize`) of a `TS_RFX_TILESET` block. Adding `numQuant *
/// RFX_CODEC_QUANT_SIZE` and `tilesDataSize` gives the total
/// `blockLen`. MS-RDPRFX 2.2.2.3.4.
pub const RFX_TILESET_FIXED_PREFIX_SIZE: usize = 22;

/// Fixed prefix (header + indices + lengths) of a `CBT_TILE` block.
/// Adding `YLen + CbLen + CrLen` gives the total `blockLen`.
/// MS-RDPRFX 2.2.2.3.4.1.
pub const RFX_TILE_FIXED_PREFIX_SIZE: usize = 19;

/// `tileSize` u8 inside `TS_RFX_TILESET` -- MUST be 0x40 (64).
/// Note: this differs from [`CT_TILE_64X64`] which is the u16 form
/// inside `TS_RFX_CONTEXT`. MS-RDPRFX 2.2.2.3.4.
pub const TILESET_TILE_SIZE: u8 = 0x40;

/// `idx` value inside `TS_RFX_TILESET` -- MUST be 0x0000.
/// MS-RDPRFX 2.2.2.3.4.
pub const TILESET_IDX: u16 = 0x0000;

// ── TS_RFX_BLOCKT ───────────────────────────────────────────────────

/// `TS_RFX_BLOCKT` -- MS-RDPRFX 2.2.2.1.1.
///
/// `block_len` includes the 6 header bytes themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfxBlockHeader {
    pub block_type: u16,
    pub block_len: u32,
}

impl Encode for RfxBlockHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.block_type, "RfxBlockHeader::blockType")?;
        dst.write_u32_le(self.block_len, "RfxBlockHeader::blockLen")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RfxBlockHeader"
    }

    fn size(&self) -> usize {
        RFX_BLOCK_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for RfxBlockHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            block_type: src.read_u16_le("RfxBlockHeader::blockType")?,
            block_len: src.read_u32_le("RfxBlockHeader::blockLen")?,
        })
    }
}

// ── TS_RFX_CODEC_CHANNELT ───────────────────────────────────────────

/// `TS_RFX_CODEC_CHANNELT` -- MS-RDPRFX 2.2.2.1.2.
///
/// Wraps [`RfxBlockHeader`] with `codecId` (MUST be [`CODEC_ID`]) and
/// `channelId` ([`CHANNEL_ID_CONTEXT`] for `WBT_CONTEXT`,
/// [`CHANNEL_ID_DATA`] for every other block that uses this header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfxCodecChannelHeader {
    pub block_type: u16,
    pub block_len: u32,
    pub codec_id: u8,
    pub channel_id: u8,
}

impl Encode for RfxCodecChannelHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.block_type, "RfxCodecChannelHeader::blockType")?;
        dst.write_u32_le(self.block_len, "RfxCodecChannelHeader::blockLen")?;
        dst.write_u8(self.codec_id, "RfxCodecChannelHeader::codecId")?;
        dst.write_u8(self.channel_id, "RfxCodecChannelHeader::channelId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RfxCodecChannelHeader"
    }

    fn size(&self) -> usize {
        RFX_CODEC_CHANNEL_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for RfxCodecChannelHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            block_type: src.read_u16_le("RfxCodecChannelHeader::blockType")?,
            block_len: src.read_u32_le("RfxCodecChannelHeader::blockLen")?,
            codec_id: src.read_u8("RfxCodecChannelHeader::codecId")?,
            channel_id: src.read_u8("RfxCodecChannelHeader::channelId")?,
        })
    }
}

// ── TS_RFX_SYNC ─────────────────────────────────────────────────────

/// `TS_RFX_SYNC` -- MS-RDPRFX 2.2.2.2.1.
///
/// Always the first block in an RFX stream. Carries no caller-controlled
/// data: every field is a fixed constant, so the struct itself is a
/// zero-sized marker and `encode()` writes the canonical 12-byte block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RfxSync;

impl Encode for RfxSync {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        RfxBlockHeader {
            block_type: WBT_SYNC,
            block_len: RFX_SYNC_SIZE as u32,
        }
        .encode(dst)?;
        dst.write_u32_le(WF_MAGIC, "RfxSync::magic")?;
        dst.write_u16_le(WF_VERSION_1_0, "RfxSync::version")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RfxSync"
    }

    fn size(&self) -> usize {
        RFX_SYNC_SIZE
    }
}

impl<'de> Decode<'de> for RfxSync {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = RfxBlockHeader::decode(src)?;
        if hdr.block_type != WBT_SYNC {
            return Err(DecodeError::unexpected_value(
                "RfxSync",
                "blockType",
                "expected WBT_SYNC (0xCCC0)",
            ));
        }
        if hdr.block_len as usize != RFX_SYNC_SIZE {
            return Err(DecodeError::invalid_value("RfxSync", "blockLen"));
        }
        let magic = src.read_u32_le("RfxSync::magic")?;
        if magic != WF_MAGIC {
            return Err(DecodeError::unexpected_value(
                "RfxSync",
                "magic",
                "expected WF_MAGIC (0xCACCACCA)",
            ));
        }
        let version = src.read_u16_le("RfxSync::version")?;
        if version != WF_VERSION_1_0 {
            return Err(DecodeError::unexpected_value(
                "RfxSync",
                "version",
                "expected WF_VERSION_1_0 (0x0100)",
            ));
        }
        Ok(Self)
    }
}

// ── TS_RFX_CODEC_VERSIONS ───────────────────────────────────────────

/// `TS_RFX_CODEC_VERSIONS` -- MS-RDPRFX 2.2.2.2.2.
///
/// Spec defines exactly one codec entry (`numCodecs = 1`,
/// `codecId = 0x01`, `version = 0x0100`); this struct is a zero-sized
/// marker and `encode()` writes the canonical 10-byte block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RfxCodecVersions;

impl Encode for RfxCodecVersions {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        RfxBlockHeader {
            block_type: WBT_CODEC_VERSIONS,
            block_len: RFX_CODEC_VERSIONS_SIZE as u32,
        }
        .encode(dst)?;
        dst.write_u8(1, "RfxCodecVersions::numCodecs")?;
        dst.write_u8(CODEC_ID, "RfxCodecVersions::codecs[0].codecId")?;
        dst.write_u16_le(WF_VERSION_1_0, "RfxCodecVersions::codecs[0].version")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RfxCodecVersions"
    }

    fn size(&self) -> usize {
        RFX_CODEC_VERSIONS_SIZE
    }
}

impl<'de> Decode<'de> for RfxCodecVersions {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = RfxBlockHeader::decode(src)?;
        if hdr.block_type != WBT_CODEC_VERSIONS {
            return Err(DecodeError::unexpected_value(
                "RfxCodecVersions",
                "blockType",
                "expected WBT_CODEC_VERSIONS (0xCCC1)",
            ));
        }
        if hdr.block_len as usize != RFX_CODEC_VERSIONS_SIZE {
            return Err(DecodeError::invalid_value(
                "RfxCodecVersions",
                "blockLen",
            ));
        }
        let num_codecs = src.read_u8("RfxCodecVersions::numCodecs")?;
        if num_codecs != 1 {
            return Err(DecodeError::unexpected_value(
                "RfxCodecVersions",
                "numCodecs",
                "expected exactly one codec entry",
            ));
        }
        let codec_id = src.read_u8("RfxCodecVersions::codecs[0].codecId")?;
        if codec_id != CODEC_ID {
            return Err(DecodeError::unexpected_value(
                "RfxCodecVersions",
                "codecId",
                "expected RFX CODEC_ID (0x01)",
            ));
        }
        let version = src.read_u16_le("RfxCodecVersions::codecs[0].version")?;
        if version != WF_VERSION_1_0 {
            return Err(DecodeError::unexpected_value(
                "RfxCodecVersions",
                "version",
                "expected WF_VERSION_1_0 (0x0100)",
            ));
        }
        Ok(Self)
    }
}

// ── TS_RFX_CHANNELT entry ───────────────────────────────────────────

/// A single `TS_RFX_CHANNELT` entry inside `WBT_CHANNELS`
/// (MS-RDPRFX 2.2.2.1.3).
///
/// `width` and `height` are signed 16-bit (per spec) but SHOULD be in
/// the ranges `[1, 4096]` and `[1, 2048]`; the encoder enforces this as
/// a hard error to avoid interop surprises (see [`RFX_MIN_CHANNEL_WIDTH`],
/// [`RFX_MAX_CHANNEL_WIDTH`], etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfxChannelEntry {
    pub channel_id: u8,
    pub width: i16,
    pub height: i16,
}

impl Encode for RfxChannelEntry {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.width < RFX_MIN_CHANNEL_WIDTH || self.width > RFX_MAX_CHANNEL_WIDTH {
            return Err(EncodeError::other(
                "RfxChannelEntry",
                "width out of MS-RDPRFX 2.2.2.1.3 range [1, 4096]",
            ));
        }
        if self.height < RFX_MIN_CHANNEL_HEIGHT || self.height > RFX_MAX_CHANNEL_HEIGHT {
            return Err(EncodeError::other(
                "RfxChannelEntry",
                "height out of MS-RDPRFX 2.2.2.1.3 range [1, 2048]",
            ));
        }
        dst.write_u8(self.channel_id, "RfxChannelEntry::channelId")?;
        dst.write_u16_le(self.width as u16, "RfxChannelEntry::width")?;
        dst.write_u16_le(self.height as u16, "RfxChannelEntry::height")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RfxChannelEntry"
    }

    fn size(&self) -> usize {
        RFX_CHANNELT_SIZE
    }
}

impl<'de> Decode<'de> for RfxChannelEntry {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        // Decode is permissive: spec says "SHOULD" be in range, and we
        // accept any signed value so a roundtrip with malformed data
        // surfaces clearly in the application layer.
        Ok(Self {
            channel_id: src.read_u8("RfxChannelEntry::channelId")?,
            width: src.read_u16_le("RfxChannelEntry::width")? as i16,
            height: src.read_u16_le("RfxChannelEntry::height")? as i16,
        })
    }
}

// ── TS_RFX_CHANNELS ─────────────────────────────────────────────────

/// `TS_RFX_CHANNELS` -- MS-RDPRFX 2.2.2.2.3.
///
/// `numChannels` (u8) places a hard cap of 255 entries; the encoder
/// guards this and `block_len` overflow before writing any byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfxChannels {
    pub channels: Vec<RfxChannelEntry>,
}

impl RfxChannels {
    fn block_len(&self) -> usize {
        RFX_BLOCK_HEADER_SIZE + 1 + self.channels.len() * RFX_CHANNELT_SIZE
    }
}

impl Encode for RfxChannels {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.channels.len() > u8::MAX as usize {
            return Err(EncodeError::other(
                "RfxChannels",
                "numChannels exceeds u8::MAX (255)",
            ));
        }
        // numChannels ≤ 255 ⇒ block_len ≤ 6 + 1 + 255*5 = 1282, so the
        // u32 cast below cannot overflow.
        let block_len = self.block_len();
        RfxBlockHeader {
            block_type: WBT_CHANNELS,
            block_len: block_len as u32,
        }
        .encode(dst)?;
        dst.write_u8(self.channels.len() as u8, "RfxChannels::numChannels")?;
        for ch in &self.channels {
            ch.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RfxChannels"
    }

    fn size(&self) -> usize {
        self.block_len()
    }
}

impl<'de> Decode<'de> for RfxChannels {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = RfxBlockHeader::decode(src)?;
        if hdr.block_type != WBT_CHANNELS {
            return Err(DecodeError::unexpected_value(
                "RfxChannels",
                "blockType",
                "expected WBT_CHANNELS (0xCCC2)",
            ));
        }
        let num_channels = src.read_u8("RfxChannels::numChannels")?;
        let expected_len = RFX_BLOCK_HEADER_SIZE
            + 1
            + (num_channels as usize) * RFX_CHANNELT_SIZE;
        if hdr.block_len as usize != expected_len {
            return Err(DecodeError::invalid_value(
                "RfxChannels",
                "blockLen does not match numChannels",
            ));
        }
        let mut channels = Vec::with_capacity(num_channels as usize);
        for _ in 0..num_channels {
            channels.push(RfxChannelEntry::decode(src)?);
        }
        Ok(Self { channels })
    }
}

// ── Properties bitfield helper ──────────────────────────────────────

/// Variable parts of the `properties` bitfield shared by `TS_RFX_CONTEXT`
/// (MS-RDPRFX 2.2.2.2.4) and `TS_RFX_TILESET` (MS-RDPRFX 2.2.2.3.4).
///
/// The two layouts are NOT identical -- TileSet inserts a `lt` (last
/// tileset) bit at LSB, shifting every other field by one bit. Pack /
/// unpack helpers per layout encapsulate this so callers never touch
/// the bit positions directly.
///
/// Fixed fields (`cct`, `xft`, `qt`) only have one valid value each
/// per the current spec and are written as that value during pack;
/// unpack accepts any value (per spec "decoder SHOULD ignore" guidance)
/// and discards them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfxProperties {
    /// `flags` (3 bits). Use [`CODEC_MODE_IMAGE`] for image-mode
    /// streams (handshake every frame).
    pub flags: u8,
    /// Entropy coder selection. Drives the `et` (4 bits) field.
    pub entropy: RlgrMode,
}

impl RfxProperties {
    /// Image-mode default (`flags = CODEC_MODE_IMAGE`) with the supplied
    /// entropy mode.
    pub const fn image(entropy: RlgrMode) -> Self {
        Self {
            flags: CODEC_MODE_IMAGE,
            entropy,
        }
    }

    fn et_bits(self) -> u16 {
        match self.entropy {
            RlgrMode::Rlgr1 => CLW_ENTROPY_RLGR1 as u16,
            RlgrMode::Rlgr3 => CLW_ENTROPY_RLGR3 as u16,
        }
    }

    fn et_from_bits(raw: u16) -> DecodeResult<RlgrMode> {
        match raw as u8 {
            CLW_ENTROPY_RLGR1 => Ok(RlgrMode::Rlgr1),
            CLW_ENTROPY_RLGR3 => Ok(RlgrMode::Rlgr3),
            _ => Err(DecodeError::unexpected_value(
                "RfxProperties",
                "et",
                "expected CLW_ENTROPY_RLGR1 (0x01) or CLW_ENTROPY_RLGR3 (0x04)",
            )),
        }
    }

    /// Pack into the `TS_RFX_CONTEXT.properties` u16 layout
    /// (MS-RDPRFX 2.2.2.2.4):
    /// `flags(3) | cct(2) | xft(4) | et(4) | qt(2) | r(1)`.
    pub fn pack_context(self) -> u16 {
        let flags = (self.flags as u16) & 0x07;
        let cct = (COL_CONV_ICT as u16) & 0x03;
        let xft = (CLW_XFORM_DWT_53_A as u16) & 0x0F;
        let et = self.et_bits() & 0x0F;
        let qt = (SCALAR_QUANTIZATION as u16) & 0x03;
        flags | (cct << 3) | (xft << 5) | (et << 9) | (qt << 13)
    }

    /// Unpack a `TS_RFX_CONTEXT.properties` u16 into the variable
    /// fields. Returns `Err` only when the `et` field has a value
    /// other than `CLW_ENTROPY_RLGR1` (0x01) or `CLW_ENTROPY_RLGR3`
    /// (0x04). Other fields (`cct`, `xft`, `qt`, `r`) are ignored
    /// per spec ("decoder SHOULD ignore").
    pub fn unpack_context(raw: u16) -> DecodeResult<Self> {
        let flags = (raw & 0x07) as u8;
        let et = (raw >> 9) & 0x0F;
        Ok(Self {
            flags,
            entropy: Self::et_from_bits(et)?,
        })
    }

    /// Pack into the `TS_RFX_TILESET.properties` u16 layout
    /// (MS-RDPRFX 2.2.2.3.4):
    /// `lt(1) | flags(3) | cct(2) | xft(4) | et(4) | qt(2)`.
    /// `lt` is hard-coded to 1 (the only valid value -- there is always
    /// exactly one TileSet per Region in the current spec).
    pub fn pack_tileset(self) -> u16 {
        let lt: u16 = 0x1;
        let flags = (self.flags as u16) & 0x07;
        let cct = (COL_CONV_ICT as u16) & 0x03;
        let xft = (CLW_XFORM_DWT_53_A as u16) & 0x0F;
        let et = self.et_bits() & 0x0F;
        let qt = (SCALAR_QUANTIZATION as u16) & 0x03;
        lt | (flags << 1) | (cct << 4) | (xft << 6) | (et << 10) | (qt << 14)
    }

    /// Unpack a `TS_RFX_TILESET.properties` u16. Same `et` validation
    /// as [`unpack_context`](Self::unpack_context); other fields
    /// (including `lt`) are ignored per spec.
    pub fn unpack_tileset(raw: u16) -> DecodeResult<Self> {
        let flags = ((raw >> 1) & 0x07) as u8;
        let et = (raw >> 10) & 0x0F;
        Ok(Self {
            flags,
            entropy: Self::et_from_bits(et)?,
        })
    }
}

// ── TS_RFX_CONTEXT ──────────────────────────────────────────────────

/// `TS_RFX_CONTEXT` -- MS-RDPRFX 2.2.2.2.4.
///
/// Carries the codec context: tile size (always 64×64), entropy mode,
/// and operational flags. Wrapped in [`RfxCodecChannelHeader`] with
/// `channelId = CHANNEL_ID_CONTEXT` (0xFF) -- the special "all
/// channels" id reserved for Context messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfxContext {
    pub properties: RfxProperties,
}

impl RfxContext {
    /// Image-mode context with the given entropy coder.
    pub const fn image(entropy: RlgrMode) -> Self {
        Self {
            properties: RfxProperties::image(entropy),
        }
    }
}

impl Encode for RfxContext {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        RfxCodecChannelHeader {
            block_type: WBT_CONTEXT,
            block_len: RFX_CONTEXT_SIZE as u32,
            codec_id: CODEC_ID,
            channel_id: CHANNEL_ID_CONTEXT,
        }
        .encode(dst)?;
        dst.write_u8(CTX_ID, "RfxContext::ctxId")?;
        dst.write_u16_le(CT_TILE_64X64, "RfxContext::tileSize")?;
        dst.write_u16_le(self.properties.pack_context(), "RfxContext::properties")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RfxContext"
    }

    fn size(&self) -> usize {
        RFX_CONTEXT_SIZE
    }
}

impl<'de> Decode<'de> for RfxContext {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = RfxCodecChannelHeader::decode(src)?;
        if hdr.block_type != WBT_CONTEXT {
            return Err(DecodeError::unexpected_value(
                "RfxContext",
                "blockType",
                "expected WBT_CONTEXT (0xCCC3)",
            ));
        }
        if hdr.block_len as usize != RFX_CONTEXT_SIZE {
            return Err(DecodeError::invalid_value("RfxContext", "blockLen"));
        }
        if hdr.codec_id != CODEC_ID {
            return Err(DecodeError::unexpected_value(
                "RfxContext",
                "codecId",
                "expected RFX CODEC_ID (0x01)",
            ));
        }
        if hdr.channel_id != CHANNEL_ID_CONTEXT {
            return Err(DecodeError::unexpected_value(
                "RfxContext",
                "channelId",
                "expected CHANNEL_ID_CONTEXT (0xFF)",
            ));
        }
        let ctx_id = src.read_u8("RfxContext::ctxId")?;
        if ctx_id != CTX_ID {
            return Err(DecodeError::unexpected_value(
                "RfxContext",
                "ctxId",
                "expected 0x00",
            ));
        }
        let tile_size = src.read_u16_le("RfxContext::tileSize")?;
        if tile_size != CT_TILE_64X64 {
            return Err(DecodeError::unexpected_value(
                "RfxContext",
                "tileSize",
                "expected CT_TILE_64X64 (0x0040)",
            ));
        }
        let raw = src.read_u16_le("RfxContext::properties")?;
        Ok(Self {
            properties: RfxProperties::unpack_context(raw)?,
        })
    }
}

// ── TS_RFX_FRAME_BEGIN ──────────────────────────────────────────────

/// `TS_RFX_FRAME_BEGIN` -- MS-RDPRFX 2.2.2.3.1.
///
/// Marks the start of an encoded frame. `numRegions` is signed per the
/// spec field type but is always positive in practice (typically 1; the
/// current spec defines exactly one Region per frame).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfxFrameBegin {
    pub frame_idx: u32,
    pub num_regions: i16,
}

impl Encode for RfxFrameBegin {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        RfxCodecChannelHeader {
            block_type: WBT_FRAME_BEGIN,
            block_len: RFX_FRAME_BEGIN_SIZE as u32,
            codec_id: CODEC_ID,
            channel_id: CHANNEL_ID_DATA,
        }
        .encode(dst)?;
        dst.write_u32_le(self.frame_idx, "RfxFrameBegin::frameIdx")?;
        dst.write_u16_le(self.num_regions as u16, "RfxFrameBegin::numRegions")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RfxFrameBegin"
    }

    fn size(&self) -> usize {
        RFX_FRAME_BEGIN_SIZE
    }
}

impl<'de> Decode<'de> for RfxFrameBegin {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = RfxCodecChannelHeader::decode(src)?;
        if hdr.block_type != WBT_FRAME_BEGIN {
            return Err(DecodeError::unexpected_value(
                "RfxFrameBegin",
                "blockType",
                "expected WBT_FRAME_BEGIN (0xCCC4)",
            ));
        }
        if hdr.block_len as usize != RFX_FRAME_BEGIN_SIZE {
            return Err(DecodeError::invalid_value("RfxFrameBegin", "blockLen"));
        }
        if hdr.codec_id != CODEC_ID {
            return Err(DecodeError::unexpected_value(
                "RfxFrameBegin",
                "codecId",
                "expected RFX CODEC_ID (0x01)",
            ));
        }
        if hdr.channel_id != CHANNEL_ID_DATA {
            return Err(DecodeError::unexpected_value(
                "RfxFrameBegin",
                "channelId",
                "expected CHANNEL_ID_DATA (0x00)",
            ));
        }
        let frame_idx = src.read_u32_le("RfxFrameBegin::frameIdx")?;
        let num_regions = src.read_u16_le("RfxFrameBegin::numRegions")? as i16;
        Ok(Self {
            frame_idx,
            num_regions,
        })
    }
}

// ── TS_RFX_FRAME_END ────────────────────────────────────────────────

/// `TS_RFX_FRAME_END` -- MS-RDPRFX 2.2.2.3.2.
///
/// End-of-frame marker. Carries no body; the 8-byte
/// `TS_RFX_CODEC_CHANNELT` header is the entire block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RfxFrameEnd;

impl Encode for RfxFrameEnd {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        RfxCodecChannelHeader {
            block_type: WBT_FRAME_END,
            block_len: RFX_FRAME_END_SIZE as u32,
            codec_id: CODEC_ID,
            channel_id: CHANNEL_ID_DATA,
        }
        .encode(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RfxFrameEnd"
    }

    fn size(&self) -> usize {
        RFX_FRAME_END_SIZE
    }
}

impl<'de> Decode<'de> for RfxFrameEnd {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = RfxCodecChannelHeader::decode(src)?;
        if hdr.block_type != WBT_FRAME_END {
            return Err(DecodeError::unexpected_value(
                "RfxFrameEnd",
                "blockType",
                "expected WBT_FRAME_END (0xCCC5)",
            ));
        }
        if hdr.block_len as usize != RFX_FRAME_END_SIZE {
            return Err(DecodeError::invalid_value("RfxFrameEnd", "blockLen"));
        }
        if hdr.codec_id != CODEC_ID {
            return Err(DecodeError::unexpected_value(
                "RfxFrameEnd",
                "codecId",
                "expected RFX CODEC_ID (0x01)",
            ));
        }
        if hdr.channel_id != CHANNEL_ID_DATA {
            return Err(DecodeError::unexpected_value(
                "RfxFrameEnd",
                "channelId",
                "expected CHANNEL_ID_DATA (0x00)",
            ));
        }
        Ok(Self)
    }
}

// ── TS_RFX_RECT ─────────────────────────────────────────────────────

/// `TS_RFX_RECT` -- MS-RDPRFX 2.2.2.1.4.
///
/// Inclusive (x, y) origin + width/height in pixels. 8 bytes fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfxRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl Encode for RfxRect {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.x, "RfxRect::x")?;
        dst.write_u16_le(self.y, "RfxRect::y")?;
        dst.write_u16_le(self.width, "RfxRect::width")?;
        dst.write_u16_le(self.height, "RfxRect::height")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RfxRect"
    }

    fn size(&self) -> usize {
        RFX_RECT_SIZE
    }
}

impl<'de> Decode<'de> for RfxRect {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            x: src.read_u16_le("RfxRect::x")?,
            y: src.read_u16_le("RfxRect::y")?,
            width: src.read_u16_le("RfxRect::width")?,
            height: src.read_u16_le("RfxRect::height")?,
        })
    }
}

// ── TS_RFX_REGION ───────────────────────────────────────────────────

/// `TS_RFX_REGION` -- MS-RDPRFX 2.2.2.3.3.
///
/// Lists destination rectangles for the upcoming TileSet.
/// `regionType` is hard-coded to [`CBT_REGION`] and `numTilesets` to
/// [`NUM_TILESETS_MUST`] (1) per spec.
///
/// `numRects = 0` is wire-legal: the spec says the receiver "MUST
/// generate a rectangle whose top-left corner is `(0, 0)` and whose
/// dimensions match the channel's width/height". The encoder allows
/// it; the decoder accepts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfxRegion {
    pub rects: Vec<RfxRect>,
}

impl RfxRegion {
    fn block_len(&self) -> usize {
        // header(8) + regionFlags(1) + numRects(2) + rects + regionType(2) + numTilesets(2)
        RFX_CODEC_CHANNEL_HEADER_SIZE + 1 + 2 + self.rects.len() * RFX_RECT_SIZE + 2 + 2
    }
}

impl Encode for RfxRegion {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.rects.len() > u16::MAX as usize {
            return Err(EncodeError::other(
                "RfxRegion",
                "numRects exceeds u16::MAX (65535)",
            ));
        }
        let block_len = self.block_len();
        if block_len > u32::MAX as usize {
            return Err(EncodeError::other(
                "RfxRegion",
                "blockLen exceeds u32::MAX",
            ));
        }
        RfxCodecChannelHeader {
            block_type: WBT_REGION,
            block_len: block_len as u32,
            codec_id: CODEC_ID,
            channel_id: CHANNEL_ID_DATA,
        }
        .encode(dst)?;
        dst.write_u8(REGION_FLAGS_LRF, "RfxRegion::regionFlags")?;
        dst.write_u16_le(self.rects.len() as u16, "RfxRegion::numRects")?;
        for r in &self.rects {
            r.encode(dst)?;
        }
        dst.write_u16_le(CBT_REGION, "RfxRegion::regionType")?;
        dst.write_u16_le(NUM_TILESETS_MUST, "RfxRegion::numTilesets")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RfxRegion"
    }

    fn size(&self) -> usize {
        self.block_len()
    }
}

impl<'de> Decode<'de> for RfxRegion {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = RfxCodecChannelHeader::decode(src)?;
        if hdr.block_type != WBT_REGION {
            return Err(DecodeError::unexpected_value(
                "RfxRegion",
                "blockType",
                "expected WBT_REGION (0xCCC6)",
            ));
        }
        if hdr.codec_id != CODEC_ID {
            return Err(DecodeError::unexpected_value(
                "RfxRegion",
                "codecId",
                "expected RFX CODEC_ID (0x01)",
            ));
        }
        if hdr.channel_id != CHANNEL_ID_DATA {
            return Err(DecodeError::unexpected_value(
                "RfxRegion",
                "channelId",
                "expected CHANNEL_ID_DATA (0x00)",
            ));
        }
        // regionFlags: spec mandates bit 0 = 1; reserved bits MUST be
        // ignored on decode.
        let region_flags = src.read_u8("RfxRegion::regionFlags")?;
        if region_flags & REGION_FLAGS_LRF == 0 {
            return Err(DecodeError::unexpected_value(
                "RfxRegion",
                "regionFlags",
                "lrf bit (bit 0) MUST be set",
            ));
        }
        let num_rects = src.read_u16_le("RfxRegion::numRects")?;
        let expected_len = RFX_CODEC_CHANNEL_HEADER_SIZE
            + 1
            + 2
            + (num_rects as usize) * RFX_RECT_SIZE
            + 2
            + 2;
        if hdr.block_len as usize != expected_len {
            return Err(DecodeError::invalid_value(
                "RfxRegion",
                "blockLen does not match numRects",
            ));
        }
        let mut rects = Vec::with_capacity(num_rects as usize);
        for _ in 0..num_rects {
            rects.push(RfxRect::decode(src)?);
        }
        let region_type = src.read_u16_le("RfxRegion::regionType")?;
        if region_type != CBT_REGION {
            return Err(DecodeError::unexpected_value(
                "RfxRegion",
                "regionType",
                "expected CBT_REGION (0xCAC1)",
            ));
        }
        let num_tilesets = src.read_u16_le("RfxRegion::numTilesets")?;
        if num_tilesets != NUM_TILESETS_MUST {
            return Err(DecodeError::unexpected_value(
                "RfxRegion",
                "numTilesets",
                "MUST be 0x0001",
            ));
        }
        Ok(Self { rects })
    }
}

// ── CBT_TILE (TS_RFX_TILE) ──────────────────────────────────────────

/// `TS_RFX_TILE` -- MS-RDPRFX 2.2.2.3.4.1.
///
/// Per-tile inner block carried inside a `WBT_EXTENSION` (TileSet)
/// payload. Uses the plain 6-byte [`RfxBlockHeader`] (no `codecId` /
/// `channelId`) -- those identifiers live on the enclosing TileSet.
///
/// `quant_idx_*` index into the enclosing TileSet's `quant_vals`.
/// `x_idx` / `y_idx` are tile positions in the 64-pixel grid (so the
/// pixel origin is `(x_idx * 64, y_idx * 64)`). `*_data` lengths
/// become the wire `YLen` / `CbLen` / `CrLen` u16 fields and are
/// therefore each capped at 65_535 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfxTileWire {
    pub quant_idx_y: u8,
    pub quant_idx_cb: u8,
    pub quant_idx_cr: u8,
    pub x_idx: u16,
    pub y_idx: u16,
    pub y_data: Vec<u8>,
    pub cb_data: Vec<u8>,
    pub cr_data: Vec<u8>,
}

impl RfxTileWire {
    fn block_len(&self) -> usize {
        RFX_TILE_FIXED_PREFIX_SIZE + self.y_data.len() + self.cb_data.len() + self.cr_data.len()
    }
}

impl Encode for RfxTileWire {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.y_data.len() > u16::MAX as usize
            || self.cb_data.len() > u16::MAX as usize
            || self.cr_data.len() > u16::MAX as usize
        {
            return Err(EncodeError::other(
                "RfxTileWire",
                "component data length exceeds u16::MAX (65535)",
            ));
        }
        let block_len = self.block_len();
        if block_len > u32::MAX as usize {
            return Err(EncodeError::other(
                "RfxTileWire",
                "blockLen exceeds u32::MAX",
            ));
        }
        RfxBlockHeader {
            block_type: CBT_TILE,
            block_len: block_len as u32,
        }
        .encode(dst)?;
        dst.write_u8(self.quant_idx_y, "RfxTileWire::quantIdxY")?;
        dst.write_u8(self.quant_idx_cb, "RfxTileWire::quantIdxCb")?;
        dst.write_u8(self.quant_idx_cr, "RfxTileWire::quantIdxCr")?;
        dst.write_u16_le(self.x_idx, "RfxTileWire::xIdx")?;
        dst.write_u16_le(self.y_idx, "RfxTileWire::yIdx")?;
        dst.write_u16_le(self.y_data.len() as u16, "RfxTileWire::YLen")?;
        dst.write_u16_le(self.cb_data.len() as u16, "RfxTileWire::CbLen")?;
        dst.write_u16_le(self.cr_data.len() as u16, "RfxTileWire::CrLen")?;
        dst.write_slice(&self.y_data, "RfxTileWire::YData")?;
        dst.write_slice(&self.cb_data, "RfxTileWire::CbData")?;
        dst.write_slice(&self.cr_data, "RfxTileWire::CrData")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RfxTileWire"
    }

    fn size(&self) -> usize {
        self.block_len()
    }
}

impl<'de> Decode<'de> for RfxTileWire {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = RfxBlockHeader::decode(src)?;
        if hdr.block_type != CBT_TILE {
            return Err(DecodeError::unexpected_value(
                "RfxTileWire",
                "blockType",
                "expected CBT_TILE (0xCAC3)",
            ));
        }
        let quant_idx_y = src.read_u8("RfxTileWire::quantIdxY")?;
        let quant_idx_cb = src.read_u8("RfxTileWire::quantIdxCb")?;
        let quant_idx_cr = src.read_u8("RfxTileWire::quantIdxCr")?;
        let x_idx = src.read_u16_le("RfxTileWire::xIdx")?;
        let y_idx = src.read_u16_le("RfxTileWire::yIdx")?;
        let y_len = src.read_u16_le("RfxTileWire::YLen")? as usize;
        let cb_len = src.read_u16_le("RfxTileWire::CbLen")? as usize;
        let cr_len = src.read_u16_le("RfxTileWire::CrLen")? as usize;
        let expected_len = RFX_TILE_FIXED_PREFIX_SIZE + y_len + cb_len + cr_len;
        if hdr.block_len as usize != expected_len {
            return Err(DecodeError::invalid_value(
                "RfxTileWire",
                "blockLen does not match Y/Cb/Cr lengths",
            ));
        }
        let y_data = src.read_slice(y_len, "RfxTileWire::YData")?.to_vec();
        let cb_data = src.read_slice(cb_len, "RfxTileWire::CbData")?.to_vec();
        let cr_data = src.read_slice(cr_len, "RfxTileWire::CrData")?.to_vec();
        Ok(Self {
            quant_idx_y,
            quant_idx_cb,
            quant_idx_cr,
            x_idx,
            y_idx,
            y_data,
            cb_data,
            cr_data,
        })
    }
}

// ── TS_RFX_TILESET (WBT_EXTENSION) ──────────────────────────────────

/// `TS_RFX_TILESET` -- MS-RDPRFX 2.2.2.3.4.
///
/// The block type on the wire is `WBT_EXTENSION` (`0xCCC7`); the
/// `subtype` field discriminates as `CBT_TILESET` (`0xCAC2`) so a
/// future extension would use the same `WBT_EXTENSION` envelope with
/// a different `subtype`.
///
/// `tileSize` field is `u8 = 0x40` -- this differs from
/// `TS_RFX_CONTEXT.tileSize` which is `u16 = 0x0040`. Both encode the
/// same value (64) but with different wire widths.
///
/// `properties.lt` (last-tileset) is hard-coded to 1: the spec
/// currently defines exactly one TileSet per Region.
///
/// `tilesDataSize` is the byte total of the `tiles` field; the encoder
/// computes it from `tiles.iter().map(|t| t.size()).sum()` and the
/// decoder cross-checks against the actual tile bytes consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfxTileSet {
    pub properties: RfxProperties,
    pub quant_vals: Vec<CodecQuant>,
    pub tiles: Vec<RfxTileWire>,
}

impl RfxTileSet {
    fn tiles_data_size(&self) -> usize {
        self.tiles.iter().map(|t| t.block_len()).sum()
    }

    fn block_len(&self) -> usize {
        RFX_TILESET_FIXED_PREFIX_SIZE
            + self.quant_vals.len() * RFX_CODEC_QUANT_SIZE
            + self.tiles_data_size()
    }
}

impl Encode for RfxTileSet {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.quant_vals.len() > u8::MAX as usize {
            return Err(EncodeError::other(
                "RfxTileSet",
                "numQuant exceeds u8::MAX (255)",
            ));
        }
        if self.tiles.len() > u16::MAX as usize {
            return Err(EncodeError::other(
                "RfxTileSet",
                "numTiles exceeds u16::MAX (65535)",
            ));
        }
        // Validate quant indices against the table size before we start
        // serialising tile bytes: catching this here gives the caller a
        // clear error rather than producing a wire-valid PDU that the
        // decoder will silently accept (decoder cannot detect this --
        // any u8 quant index is structurally valid).
        let num_quant = self.quant_vals.len();
        for (i, t) in self.tiles.iter().enumerate() {
            for (idx, label) in [
                (t.quant_idx_y, "Y"),
                (t.quant_idx_cb, "Cb"),
                (t.quant_idx_cr, "Cr"),
            ] {
                if (idx as usize) >= num_quant {
                    let _ = (i, label); // names unused outside debug builds
                    return Err(EncodeError::other(
                        "RfxTileSet",
                        "tile quantIdx out of range for TileSet quant_vals",
                    ));
                }
            }
        }
        let tiles_data_size = self.tiles_data_size();
        if tiles_data_size > u32::MAX as usize {
            return Err(EncodeError::other(
                "RfxTileSet",
                "tilesDataSize exceeds u32::MAX",
            ));
        }
        let block_len = self.block_len();
        if block_len > u32::MAX as usize {
            return Err(EncodeError::other(
                "RfxTileSet",
                "blockLen exceeds u32::MAX",
            ));
        }
        RfxCodecChannelHeader {
            block_type: WBT_EXTENSION,
            block_len: block_len as u32,
            codec_id: CODEC_ID,
            channel_id: CHANNEL_ID_DATA,
        }
        .encode(dst)?;
        dst.write_u16_le(CBT_TILESET, "RfxTileSet::subtype")?;
        dst.write_u16_le(TILESET_IDX, "RfxTileSet::idx")?;
        dst.write_u16_le(self.properties.pack_tileset(), "RfxTileSet::properties")?;
        dst.write_u8(num_quant as u8, "RfxTileSet::numQuant")?;
        dst.write_u8(TILESET_TILE_SIZE, "RfxTileSet::tileSize")?;
        dst.write_u16_le(self.tiles.len() as u16, "RfxTileSet::numTiles")?;
        dst.write_u32_le(tiles_data_size as u32, "RfxTileSet::tilesDataSize")?;
        for q in &self.quant_vals {
            let bytes = q.to_bytes();
            dst.write_slice(&bytes, "RfxTileSet::quantVals[i]")?;
        }
        for t in &self.tiles {
            t.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RfxTileSet"
    }

    fn size(&self) -> usize {
        self.block_len()
    }
}

impl<'de> Decode<'de> for RfxTileSet {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = RfxCodecChannelHeader::decode(src)?;
        if hdr.block_type != WBT_EXTENSION {
            return Err(DecodeError::unexpected_value(
                "RfxTileSet",
                "blockType",
                "expected WBT_EXTENSION (0xCCC7)",
            ));
        }
        if hdr.codec_id != CODEC_ID {
            return Err(DecodeError::unexpected_value(
                "RfxTileSet",
                "codecId",
                "expected RFX CODEC_ID (0x01)",
            ));
        }
        if hdr.channel_id != CHANNEL_ID_DATA {
            return Err(DecodeError::unexpected_value(
                "RfxTileSet",
                "channelId",
                "expected CHANNEL_ID_DATA (0x00)",
            ));
        }
        let subtype = src.read_u16_le("RfxTileSet::subtype")?;
        if subtype != CBT_TILESET {
            return Err(DecodeError::unexpected_value(
                "RfxTileSet",
                "subtype",
                "expected CBT_TILESET (0xCAC2)",
            ));
        }
        // `idx` MUST be 0; we follow spec MUST and reject other values.
        let idx = src.read_u16_le("RfxTileSet::idx")?;
        if idx != TILESET_IDX {
            return Err(DecodeError::unexpected_value(
                "RfxTileSet",
                "idx",
                "expected 0x0000",
            ));
        }
        let raw_props = src.read_u16_le("RfxTileSet::properties")?;
        let properties = RfxProperties::unpack_tileset(raw_props)?;
        let num_quant = src.read_u8("RfxTileSet::numQuant")?;
        let tile_size = src.read_u8("RfxTileSet::tileSize")?;
        if tile_size != TILESET_TILE_SIZE {
            return Err(DecodeError::unexpected_value(
                "RfxTileSet",
                "tileSize",
                "expected 0x40",
            ));
        }
        let num_tiles = src.read_u16_le("RfxTileSet::numTiles")?;
        let tiles_data_size = src.read_u32_le("RfxTileSet::tilesDataSize")? as usize;

        let expected_len = RFX_TILESET_FIXED_PREFIX_SIZE
            + (num_quant as usize) * RFX_CODEC_QUANT_SIZE
            + tiles_data_size;
        if hdr.block_len as usize != expected_len {
            return Err(DecodeError::invalid_value(
                "RfxTileSet",
                "blockLen does not match numQuant + tilesDataSize",
            ));
        }

        let mut quant_vals = Vec::with_capacity(num_quant as usize);
        for _ in 0..num_quant {
            let bytes = src.read_slice(RFX_CODEC_QUANT_SIZE, "RfxTileSet::quantVals[i]")?;
            // `read_slice` returns a borrow; copy into a fixed array
            // for `CodecQuant::from_bytes`.
            let mut buf = [0u8; RFX_CODEC_QUANT_SIZE];
            buf.copy_from_slice(bytes);
            quant_vals.push(CodecQuant::from_bytes(&buf));
        }

        let tiles_start = src.pos();
        let mut tiles = Vec::with_capacity(num_tiles as usize);
        for _ in 0..num_tiles {
            tiles.push(RfxTileWire::decode(src)?);
        }
        let tiles_consumed = src.pos() - tiles_start;
        if tiles_consumed != tiles_data_size {
            return Err(DecodeError::invalid_value(
                "RfxTileSet",
                "actual tile bytes consumed do not match tilesDataSize",
            ));
        }

        Ok(Self {
            properties,
            quant_vals,
            tiles,
        })
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
            "size() must match encode() output for {}",
            value.name(),
        );
        let mut src = ReadCursor::new(&buf[..written]);
        let decoded = T::decode(&mut src).expect("decode");
        assert_eq!(src.remaining(), 0, "leftover bytes after decode");
        decoded
    }

    #[test]
    fn block_header_roundtrip() {
        let h = RfxBlockHeader {
            block_type: WBT_SYNC,
            block_len: 12,
        };
        let d = roundtrip(&h);
        assert_eq!(d, h);
    }

    #[test]
    fn codec_channel_header_roundtrip_context_and_data_channels() {
        for (block_type, channel_id) in [
            (WBT_CONTEXT, CHANNEL_ID_CONTEXT),
            (WBT_FRAME_BEGIN, CHANNEL_ID_DATA),
            (WBT_REGION, CHANNEL_ID_DATA),
        ] {
            let h = RfxCodecChannelHeader {
                block_type,
                block_len: 100,
                codec_id: CODEC_ID,
                channel_id,
            };
            let d = roundtrip(&h);
            assert_eq!(d, h);
        }
    }

    #[test]
    fn rfx_sync_roundtrip_and_byte_layout() {
        let s = RfxSync;
        let d = roundtrip(&s);
        assert_eq!(d, s);

        let mut buf = vec![0u8; RFX_SYNC_SIZE];
        s.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // Manual layout sanity: blockType LE | blockLen LE | magic LE | version LE.
        assert_eq!(&buf[..2], &[0xC0, 0xCC]);
        assert_eq!(&buf[2..6], &[0x0C, 0x00, 0x00, 0x00]);
        assert_eq!(&buf[6..10], &[0xCA, 0xAC, 0xCC, 0xCA]);
        assert_eq!(&buf[10..12], &[0x00, 0x01]);
    }

    #[test]
    fn rfx_sync_decode_rejects_bad_magic() {
        let mut buf = vec![0u8; RFX_SYNC_SIZE];
        RfxSync.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // Corrupt magic byte 0.
        buf[6] = 0x00;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxSync::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_sync_decode_rejects_bad_version() {
        let mut buf = vec![0u8; RFX_SYNC_SIZE];
        RfxSync.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // Corrupt version low byte.
        buf[10] = 0xFF;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxSync::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_sync_decode_rejects_wrong_block_type() {
        let mut buf = vec![0u8; RFX_SYNC_SIZE];
        RfxSync.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[0] = 0xC2; // WBT_CHANNELS low byte instead of WBT_SYNC's 0xC0
        let mut src = ReadCursor::new(&buf);
        assert!(RfxSync::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_codec_versions_roundtrip_and_size() {
        let v = RfxCodecVersions;
        let d = roundtrip(&v);
        assert_eq!(d, v);
        assert_eq!(v.size(), RFX_CODEC_VERSIONS_SIZE);
        assert_eq!(RFX_CODEC_VERSIONS_SIZE, 10);
    }

    #[test]
    fn rfx_codec_versions_decode_rejects_wrong_num_codecs() {
        let mut buf = vec![0u8; RFX_CODEC_VERSIONS_SIZE];
        RfxCodecVersions
            .encode(&mut WriteCursor::new(&mut buf))
            .unwrap();
        buf[6] = 2; // numCodecs
        let mut src = ReadCursor::new(&buf);
        assert!(RfxCodecVersions::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_sync_decode_rejects_wrong_block_len() {
        let mut buf = vec![0u8; RFX_SYNC_SIZE];
        RfxSync.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // blockLen bytes 2..6 -- claim 0xFF instead of 0x0C.
        buf[2] = 0xFF;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxSync::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_codec_versions_decode_rejects_wrong_version() {
        let mut buf = vec![0u8; RFX_CODEC_VERSIONS_SIZE];
        RfxCodecVersions
            .encode(&mut WriteCursor::new(&mut buf))
            .unwrap();
        // version u16 LE at byte offset 8 (6 header + 1 numCodecs + 1 codecId).
        buf[8] = 0x02;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxCodecVersions::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_codec_versions_decode_rejects_wrong_codec_id() {
        let mut buf = vec![0u8; RFX_CODEC_VERSIONS_SIZE];
        RfxCodecVersions
            .encode(&mut WriteCursor::new(&mut buf))
            .unwrap();
        buf[7] = 0x02;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxCodecVersions::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_channel_entry_roundtrip_at_max_dimensions() {
        let e = RfxChannelEntry {
            channel_id: CHANNEL_ID_DATA,
            width: RFX_MAX_CHANNEL_WIDTH,
            height: RFX_MAX_CHANNEL_HEIGHT,
        };
        let d = roundtrip(&e);
        assert_eq!(d, e);
        assert_eq!(e.size(), RFX_CHANNELT_SIZE);
    }

    #[test]
    fn rfx_channel_entry_encode_rejects_out_of_range() {
        let too_wide = RfxChannelEntry {
            channel_id: 0,
            width: RFX_MAX_CHANNEL_WIDTH + 1,
            height: 1080,
        };
        let mut buf = [0u8; RFX_CHANNELT_SIZE];
        assert!(too_wide.encode(&mut WriteCursor::new(&mut buf)).is_err());
        let too_tall = RfxChannelEntry {
            channel_id: 0,
            width: 1920,
            height: RFX_MAX_CHANNEL_HEIGHT + 1,
        };
        assert!(too_tall.encode(&mut WriteCursor::new(&mut buf)).is_err());
        let zero_w = RfxChannelEntry {
            channel_id: 0,
            width: 0,
            height: 1,
        };
        assert!(zero_w.encode(&mut WriteCursor::new(&mut buf)).is_err());
        let neg_h = RfxChannelEntry {
            channel_id: 0,
            width: 1,
            height: -1,
        };
        assert!(neg_h.encode(&mut WriteCursor::new(&mut buf)).is_err());
    }

    #[test]
    fn rfx_channel_entry_decode_accepts_out_of_range_for_inspection() {
        // Decode must not enforce the range so that an application
        // observing a malformed wire stream sees the actual values.
        let bytes = [
            CHANNEL_ID_DATA,
            0xFF, 0xFF, // width = -1 i16
            0x00, 0x00, // height = 0
        ];
        let mut src = ReadCursor::new(&bytes);
        let e = RfxChannelEntry::decode(&mut src).unwrap();
        assert_eq!(e.width, -1);
        assert_eq!(e.height, 0);
    }

    #[test]
    fn rfx_channels_single_channel_roundtrip() {
        let c = RfxChannels {
            channels: vec![RfxChannelEntry {
                channel_id: CHANNEL_ID_DATA,
                width: 1920,
                height: 1080,
            }],
        };
        let d = roundtrip(&c);
        assert_eq!(d, c);
        // Spec block_len = 6 (header) + 1 (numChannels) + 5 (channel entry) = 12.
        assert_eq!(c.size(), 12);
    }

    #[test]
    fn rfx_channels_empty_roundtrip() {
        // numChannels = 0 is wire-legal even if not useful in practice.
        let c = RfxChannels { channels: vec![] };
        let d = roundtrip(&c);
        assert_eq!(d, c);
        assert_eq!(c.size(), 7);
    }

    #[test]
    fn rfx_channels_multi_channel_roundtrip() {
        let c = RfxChannels {
            channels: vec![
                RfxChannelEntry {
                    channel_id: CHANNEL_ID_DATA,
                    width: 1920,
                    height: 1080,
                },
                RfxChannelEntry {
                    channel_id: CHANNEL_ID_DATA,
                    width: 2560,
                    height: 1440,
                },
                RfxChannelEntry {
                    channel_id: CHANNEL_ID_DATA,
                    width: 640,
                    height: 480,
                },
            ],
        };
        let d = roundtrip(&c);
        assert_eq!(d, c);
        assert_eq!(c.size(), 7 + 3 * RFX_CHANNELT_SIZE);
    }

    #[test]
    fn rfx_channels_encode_propagates_entry_range_error() {
        let c = RfxChannels {
            channels: vec![RfxChannelEntry {
                channel_id: 0,
                width: 99_99, // > 4096
                height: 1080,
            }],
        };
        let mut buf = vec![0u8; c.size()];
        assert!(c.encode(&mut WriteCursor::new(&mut buf)).is_err());
    }

    #[test]
    fn rfx_channels_decode_rejects_wrong_block_type() {
        let c = RfxChannels {
            channels: vec![RfxChannelEntry {
                channel_id: 0,
                width: 800,
                height: 600,
            }],
        };
        let mut buf = vec![0u8; c.size()];
        c.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // blockType bytes 0..2 -- corrupt low byte to make it WBT_SYNC (0xCCC0).
        buf[0] = 0xC0;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxChannels::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_channels_encode_at_max_num_channels() {
        // u8::MAX = 255 entries: encode succeeds and blockLen reflects the
        // full 7 + 5*255 = 1282 byte payload.
        let mut entries = Vec::with_capacity(255);
        for i in 0..255 {
            entries.push(RfxChannelEntry {
                channel_id: 0,
                width: ((i % 4096) + 1) as i16,
                height: ((i % 2048) + 1) as i16,
            });
        }
        let c = RfxChannels { channels: entries };
        assert_eq!(c.size(), 7 + 255 * RFX_CHANNELT_SIZE);
        let d = roundtrip(&c);
        assert_eq!(d.channels.len(), 255);
    }

    #[test]
    fn rfx_channels_encode_rejects_more_than_u8_max_entries() {
        let entries = (0..256)
            .map(|_| RfxChannelEntry {
                channel_id: 0,
                width: 800,
                height: 600,
            })
            .collect::<Vec<_>>();
        let c = RfxChannels { channels: entries };
        let mut buf = vec![0u8; c.size()];
        assert!(c.encode(&mut WriteCursor::new(&mut buf)).is_err());
    }

    #[test]
    fn rfx_properties_pack_context_rlgr1_matches_spec_layout() {
        // image-mode + RLGR1: flags=0x02, cct=0x1, xft=0x1, et=0x01, qt=0x1
        // = 0x02 | (0x1<<3) | (0x1<<5) | (0x01<<9) | (0x1<<13)
        // = 0x0002 | 0x0008 | 0x0020 | 0x0200 | 0x2000 = 0x222A
        let p = RfxProperties::image(RlgrMode::Rlgr1);
        assert_eq!(p.pack_context(), 0x222A);
    }

    #[test]
    fn rfx_properties_pack_context_rlgr3_matches_spec_layout() {
        // image-mode + RLGR3: flags=0x02, et=0x04 → 0x02 | 0x08 | 0x20 | (0x04<<9) | 0x2000
        // (0x04 << 9) = 0x0800; total = 0x282A
        let p = RfxProperties::image(RlgrMode::Rlgr3);
        assert_eq!(p.pack_context(), 0x282A);
    }

    #[test]
    fn rfx_properties_pack_tileset_rlgr3_matches_spec_layout() {
        // tileset image-mode + RLGR3: lt=1, flags=0x02, cct=0x1, xft=0x1, et=0x04, qt=0x1
        // = 0x1 | (0x02<<1) | (0x1<<4) | (0x1<<6) | (0x04<<10) | (0x1<<14)
        // = 0x0001 | 0x0004 | 0x0010 | 0x0040 | 0x1000 | 0x4000 = 0x5055
        let p = RfxProperties::image(RlgrMode::Rlgr3);
        assert_eq!(p.pack_tileset(), 0x5055);
    }

    #[test]
    fn rfx_properties_pack_tileset_rlgr1_matches_spec_layout() {
        // tileset image-mode + RLGR1: lt=1, flags=0x02, cct=0x1, xft=0x1, et=0x01, qt=0x1
        // = 0x1 | 0x4 | 0x10 | 0x40 | (0x01<<10) | 0x4000
        // = 0x0001 | 0x0004 | 0x0010 | 0x0040 | 0x0400 | 0x4000 = 0x4455
        let p = RfxProperties::image(RlgrMode::Rlgr1);
        assert_eq!(p.pack_tileset(), 0x4455);
    }

    #[test]
    fn rfx_properties_pack_tileset_lt_bit_always_set() {
        for entropy in [RlgrMode::Rlgr1, RlgrMode::Rlgr3] {
            for flags in 0..=0x07_u8 {
                let p = RfxProperties { flags, entropy };
                assert_eq!(
                    p.pack_tileset() & 0x1,
                    0x1,
                    "lt bit must always be set",
                );
            }
        }
    }

    #[test]
    fn rfx_properties_unpack_context_roundtrip_both_modes() {
        for entropy in [RlgrMode::Rlgr1, RlgrMode::Rlgr3] {
            let p = RfxProperties::image(entropy);
            let raw = p.pack_context();
            let d = RfxProperties::unpack_context(raw).unwrap();
            assert_eq!(d, p);
        }
    }

    #[test]
    fn rfx_properties_unpack_tileset_roundtrip_both_modes() {
        for entropy in [RlgrMode::Rlgr1, RlgrMode::Rlgr3] {
            let p = RfxProperties::image(entropy);
            let raw = p.pack_tileset();
            let d = RfxProperties::unpack_tileset(raw).unwrap();
            assert_eq!(d, p);
        }
    }

    #[test]
    fn rfx_properties_unpack_context_rejects_unknown_et() {
        // Same Context layout but et = 0x07 (undefined).
        let raw = (0x02_u16) | (0x1 << 3) | (0x1 << 5) | (0x07 << 9) | (0x1 << 13);
        assert!(RfxProperties::unpack_context(raw).is_err());
    }

    #[test]
    fn rfx_properties_unpack_tileset_rejects_unknown_et() {
        let raw = 0x1_u16 | (0x02 << 1) | (0x1 << 4) | (0x1 << 6) | (0x07 << 10) | (0x1 << 14);
        assert!(RfxProperties::unpack_tileset(raw).is_err());
    }

    #[test]
    fn rfx_properties_unpack_context_ignores_reserved_and_must_fields() {
        // Construct a Context properties word with cct=0x3, xft=0x5, qt=0x2,
        // r=1 — all of which are spec-illegal — and verify the decoder
        // still recovers the variable parts (flags, et) successfully.
        let flags = 0x02_u16;
        let et = CLW_ENTROPY_RLGR1 as u16;
        let raw = flags | (0x3 << 3) | (0x5 << 5) | (et << 9) | (0x2 << 13) | (0x1 << 15);
        let d = RfxProperties::unpack_context(raw).unwrap();
        assert_eq!(d.flags, 0x02);
        assert!(matches!(d.entropy, RlgrMode::Rlgr1));
    }

    #[test]
    fn rfx_context_roundtrip_rlgr1() {
        let c = RfxContext::image(RlgrMode::Rlgr1);
        let d = roundtrip(&c);
        assert_eq!(d, c);
        assert_eq!(c.size(), RFX_CONTEXT_SIZE);
    }

    #[test]
    fn rfx_context_roundtrip_rlgr3() {
        let c = RfxContext::image(RlgrMode::Rlgr3);
        let d = roundtrip(&c);
        assert_eq!(d, c);
    }

    #[test]
    fn rfx_context_byte_layout_uses_context_channel_id() {
        let c = RfxContext::image(RlgrMode::Rlgr3);
        let mut buf = vec![0u8; RFX_CONTEXT_SIZE];
        c.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // codecId at byte 6, channelId at byte 7.
        assert_eq!(buf[6], CODEC_ID);
        assert_eq!(buf[7], CHANNEL_ID_CONTEXT);
        // ctxId at byte 8.
        assert_eq!(buf[8], 0x00);
        // tileSize u16 LE at bytes 9..11.
        assert_eq!(&buf[9..11], &[0x40, 0x00]);
    }

    #[test]
    fn rfx_context_decode_rejects_wrong_block_type() {
        let c = RfxContext::image(RlgrMode::Rlgr1);
        let mut buf = vec![0u8; RFX_CONTEXT_SIZE];
        c.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[0] = 0xC0; // WBT_SYNC instead of WBT_CONTEXT
        let mut src = ReadCursor::new(&buf);
        assert!(RfxContext::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_context_decode_rejects_wrong_codec_id() {
        let c = RfxContext::image(RlgrMode::Rlgr1);
        let mut buf = vec![0u8; RFX_CONTEXT_SIZE];
        c.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[6] = 0x02; // codecId byte
        let mut src = ReadCursor::new(&buf);
        assert!(RfxContext::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_context_decode_rejects_wrong_channel_id() {
        let c = RfxContext::image(RlgrMode::Rlgr1);
        let mut buf = vec![0u8; RFX_CONTEXT_SIZE];
        c.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[7] = CHANNEL_ID_DATA; // 0x00 instead of 0xFF
        let mut src = ReadCursor::new(&buf);
        assert!(RfxContext::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_context_decode_rejects_wrong_ctx_id() {
        let c = RfxContext::image(RlgrMode::Rlgr1);
        let mut buf = vec![0u8; RFX_CONTEXT_SIZE];
        c.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[8] = 0x01;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxContext::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_context_decode_rejects_wrong_tile_size() {
        let c = RfxContext::image(RlgrMode::Rlgr1);
        let mut buf = vec![0u8; RFX_CONTEXT_SIZE];
        c.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[9] = 0x80; // tileSize=0x0080 instead of 0x0040
        let mut src = ReadCursor::new(&buf);
        assert!(RfxContext::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_context_decode_rejects_wrong_block_len() {
        let c = RfxContext::image(RlgrMode::Rlgr1);
        let mut buf = vec![0u8; RFX_CONTEXT_SIZE];
        c.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[2] = 0xFF;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxContext::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_channels_decode_rejects_blocklen_mismatch() {
        let c = RfxChannels {
            channels: vec![RfxChannelEntry {
                channel_id: 0,
                width: 800,
                height: 600,
            }],
        };
        let mut buf = vec![0u8; c.size()];
        c.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // Corrupt blockLen to claim 100 bytes -- decoder MUST reject.
        buf[2] = 100;
        buf[3] = 0;
        buf[4] = 0;
        buf[5] = 0;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxChannels::decode(&mut src).is_err());
    }

    // ── FRAME_BEGIN tests ────────────────────────────────────────

    #[test]
    fn rfx_frame_begin_roundtrip_zero() {
        let f = RfxFrameBegin {
            frame_idx: 0,
            num_regions: 1,
        };
        let d = roundtrip(&f);
        assert_eq!(d, f);
        assert_eq!(f.size(), RFX_FRAME_BEGIN_SIZE);
    }

    #[test]
    fn rfx_frame_begin_roundtrip_max_frame_idx() {
        let f = RfxFrameBegin {
            frame_idx: u32::MAX,
            num_regions: 1,
        };
        let d = roundtrip(&f);
        assert_eq!(d, f);
    }

    #[test]
    fn rfx_frame_begin_byte_layout() {
        let f = RfxFrameBegin {
            frame_idx: 0x0102_0304,
            num_regions: 1,
        };
        let mut buf = vec![0u8; RFX_FRAME_BEGIN_SIZE];
        f.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // header bytes 0..2 = blockType WBT_FRAME_BEGIN (0xCCC4) LE.
        assert_eq!(&buf[..2], &[0xC4, 0xCC]);
        // bytes 2..6 = blockLen 14 LE.
        assert_eq!(&buf[2..6], &[0x0E, 0x00, 0x00, 0x00]);
        // codecId/channelId.
        assert_eq!(buf[6], CODEC_ID);
        assert_eq!(buf[7], CHANNEL_ID_DATA);
        // frameIdx LE bytes 8..12.
        assert_eq!(&buf[8..12], &[0x04, 0x03, 0x02, 0x01]);
        // numRegions LE bytes 12..14.
        assert_eq!(&buf[12..14], &[0x01, 0x00]);
    }

    #[test]
    fn rfx_frame_begin_roundtrip_negative_num_regions() {
        // numRegions is i16; verify the two's-complement cast roundtrips
        // for i16::MIN (worst case for sign extension).
        let f = RfxFrameBegin {
            frame_idx: 0xCAFEBABE,
            num_regions: i16::MIN,
        };
        let d = roundtrip(&f);
        assert_eq!(d, f);
    }

    #[test]
    fn rfx_frame_begin_decode_rejects_wrong_block_len() {
        let f = RfxFrameBegin {
            frame_idx: 0,
            num_regions: 1,
        };
        let mut buf = vec![0u8; RFX_FRAME_BEGIN_SIZE];
        f.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[2] = 0xFF;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxFrameBegin::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_frame_begin_decode_rejects_wrong_codec_id() {
        let f = RfxFrameBegin {
            frame_idx: 0,
            num_regions: 1,
        };
        let mut buf = vec![0u8; RFX_FRAME_BEGIN_SIZE];
        f.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[6] = 0x02;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxFrameBegin::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_frame_begin_decode_rejects_wrong_block_type() {
        let f = RfxFrameBegin {
            frame_idx: 1,
            num_regions: 1,
        };
        let mut buf = vec![0u8; RFX_FRAME_BEGIN_SIZE];
        f.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[0] = 0xC0; // -> WBT_SYNC
        let mut src = ReadCursor::new(&buf);
        assert!(RfxFrameBegin::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_frame_begin_decode_rejects_wrong_channel_id() {
        let f = RfxFrameBegin {
            frame_idx: 1,
            num_regions: 1,
        };
        let mut buf = vec![0u8; RFX_FRAME_BEGIN_SIZE];
        f.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[7] = CHANNEL_ID_CONTEXT;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxFrameBegin::decode(&mut src).is_err());
    }

    // ── FRAME_END tests ──────────────────────────────────────────

    #[test]
    fn rfx_frame_end_roundtrip() {
        let f = RfxFrameEnd;
        let d = roundtrip(&f);
        assert_eq!(d, f);
        assert_eq!(f.size(), RFX_FRAME_END_SIZE);
    }

    #[test]
    fn rfx_frame_end_byte_layout() {
        let f = RfxFrameEnd;
        let mut buf = vec![0u8; RFX_FRAME_END_SIZE];
        f.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        assert_eq!(&buf[..2], &[0xC5, 0xCC]); // WBT_FRAME_END (0xCCC5) LE
        assert_eq!(&buf[2..6], &[0x08, 0x00, 0x00, 0x00]); // blockLen=8
        assert_eq!(buf[6], CODEC_ID);
        assert_eq!(buf[7], CHANNEL_ID_DATA);
    }

    #[test]
    fn rfx_frame_end_decode_rejects_wrong_block_type() {
        let f = RfxFrameEnd;
        let mut buf = vec![0u8; RFX_FRAME_END_SIZE];
        f.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[0] = 0xC0; // -> WBT_SYNC
        let mut src = ReadCursor::new(&buf);
        assert!(RfxFrameEnd::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_frame_end_decode_rejects_wrong_codec_id() {
        let f = RfxFrameEnd;
        let mut buf = vec![0u8; RFX_FRAME_END_SIZE];
        f.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[6] = 0x02;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxFrameEnd::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_frame_end_decode_rejects_wrong_channel_id() {
        let f = RfxFrameEnd;
        let mut buf = vec![0u8; RFX_FRAME_END_SIZE];
        f.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[7] = CHANNEL_ID_CONTEXT;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxFrameEnd::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_frame_end_decode_rejects_wrong_block_len() {
        let f = RfxFrameEnd;
        let mut buf = vec![0u8; RFX_FRAME_END_SIZE];
        f.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[2] = 0xFF;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxFrameEnd::decode(&mut src).is_err());
    }

    // ── RECT + REGION tests ──────────────────────────────────────

    #[test]
    fn rfx_rect_roundtrip() {
        let r = RfxRect {
            x: 10,
            y: 20,
            width: 100,
            height: 50,
        };
        let d = roundtrip(&r);
        assert_eq!(d, r);
        assert_eq!(r.size(), RFX_RECT_SIZE);
    }

    #[test]
    fn rfx_rect_boundary_values_roundtrip() {
        for r in [
            RfxRect { x: 0, y: 0, width: 0, height: 0 },
            RfxRect {
                x: u16::MAX,
                y: u16::MAX,
                width: u16::MAX,
                height: u16::MAX,
            },
            RfxRect { x: 0, y: u16::MAX, width: u16::MAX, height: 0 },
        ] {
            let d = roundtrip(&r);
            assert_eq!(d, r);
        }
    }

    #[test]
    fn rfx_rect_byte_layout() {
        let r = RfxRect {
            x: 0x0102,
            y: 0x0304,
            width: 0x0506,
            height: 0x0708,
        };
        let mut buf = [0u8; RFX_RECT_SIZE];
        r.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // x → y → width → height, all u16 LE.
        assert_eq!(&buf, &[0x02, 0x01, 0x04, 0x03, 0x06, 0x05, 0x08, 0x07]);
    }

    #[test]
    fn rfx_region_zero_rects_roundtrip() {
        let r = RfxRegion { rects: vec![] };
        let d = roundtrip(&r);
        assert_eq!(d, r);
        // header(8) + regionFlags(1) + numRects(2) + 0 + regionType(2) + numTilesets(2) = 15
        assert_eq!(r.size(), 15);
    }

    #[test]
    fn rfx_region_single_rect_roundtrip() {
        let r = RfxRegion {
            rects: vec![RfxRect {
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
            }],
        };
        let d = roundtrip(&r);
        assert_eq!(d, r);
        assert_eq!(r.size(), 15 + 8);
    }

    #[test]
    fn rfx_region_multi_rect_roundtrip() {
        let rects = (0..5)
            .map(|i| RfxRect {
                x: i * 100,
                y: i * 100,
                width: 64,
                height: 64,
            })
            .collect::<Vec<_>>();
        let r = RfxRegion { rects };
        let d = roundtrip(&r);
        assert_eq!(d, r);
        assert_eq!(r.size(), 15 + 5 * 8);
    }

    #[test]
    fn rfx_region_byte_layout_constants() {
        let r = RfxRegion {
            rects: vec![RfxRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            }],
        };
        let mut buf = vec![0u8; r.size()];
        r.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // header
        assert_eq!(&buf[..2], &[0xC6, 0xCC]); // WBT_REGION
        // blockLen = 23 = 15 + 8
        assert_eq!(&buf[2..6], &[0x17, 0x00, 0x00, 0x00]);
        assert_eq!(buf[6], CODEC_ID);
        assert_eq!(buf[7], CHANNEL_ID_DATA);
        // regionFlags
        assert_eq!(buf[8], REGION_FLAGS_LRF);
        // numRects=1
        assert_eq!(&buf[9..11], &[0x01, 0x00]);
        // skip 8B rect
        // regionType = 0xCAC1 LE
        assert_eq!(&buf[19..21], &[0xC1, 0xCA]);
        // numTilesets = 0x0001 LE
        assert_eq!(&buf[21..23], &[0x01, 0x00]);
    }

    #[test]
    fn rfx_region_decode_rejects_wrong_block_type() {
        let r = RfxRegion { rects: vec![] };
        let mut buf = vec![0u8; r.size()];
        r.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[0] = 0xC0; // -> WBT_SYNC
        let mut src = ReadCursor::new(&buf);
        assert!(RfxRegion::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_region_decode_rejects_wrong_codec_id() {
        let r = RfxRegion { rects: vec![] };
        let mut buf = vec![0u8; r.size()];
        r.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[6] = 0x02;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxRegion::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_region_decode_rejects_wrong_channel_id() {
        let r = RfxRegion { rects: vec![] };
        let mut buf = vec![0u8; r.size()];
        r.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[7] = CHANNEL_ID_CONTEXT;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxRegion::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_region_decode_rejects_wrong_region_type() {
        let r = RfxRegion {
            rects: vec![RfxRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            }],
        };
        let mut buf = vec![0u8; r.size()];
        r.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // regionType is at offset 19..21; write 0xCAC2 (CBT_TILESET) instead.
        buf[19] = 0xC2;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxRegion::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_region_decode_rejects_wrong_num_tilesets() {
        let r = RfxRegion {
            rects: vec![RfxRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            }],
        };
        let mut buf = vec![0u8; r.size()];
        r.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // numTilesets at offset 21..23; corrupt to 0x0002.
        buf[21] = 0x02;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxRegion::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_region_decode_rejects_lrf_bit_unset() {
        let r = RfxRegion { rects: vec![] };
        let mut buf = vec![0u8; r.size()];
        r.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[8] = 0x00; // clear lrf
        let mut src = ReadCursor::new(&buf);
        assert!(RfxRegion::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_region_decode_accepts_reserved_bits_in_region_flags() {
        let r = RfxRegion { rects: vec![] };
        let mut buf = vec![0u8; r.size()];
        r.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[8] = REGION_FLAGS_LRF | 0xFE; // set every reserved bit
        let mut src = ReadCursor::new(&buf);
        let d = RfxRegion::decode(&mut src).unwrap();
        assert_eq!(d.rects.len(), 0);
    }

    // ── TILE + TILESET tests ─────────────────────────────────────

    fn sample_tile(quant_idx: u8, x_idx: u16, y_idx: u16, bytes_each: usize) -> RfxTileWire {
        RfxTileWire {
            quant_idx_y: quant_idx,
            quant_idx_cb: quant_idx,
            quant_idx_cr: quant_idx,
            x_idx,
            y_idx,
            y_data: vec![0xAA; bytes_each],
            cb_data: vec![0xBB; bytes_each],
            cr_data: vec![0xCC; bytes_each],
        }
    }

    fn sample_quant() -> CodecQuant {
        CodecQuant::from_bytes(&[0x66, 0x66, 0x66, 0x66, 0x66])
    }

    #[test]
    fn rfx_tile_wire_roundtrip_small() {
        let t = sample_tile(0, 1, 2, 32);
        let d = roundtrip(&t);
        assert_eq!(d, t);
        assert_eq!(t.size(), RFX_TILE_FIXED_PREFIX_SIZE + 32 * 3);
    }

    #[test]
    fn rfx_tile_wire_roundtrip_zero_length_components() {
        let t = RfxTileWire {
            quant_idx_y: 0,
            quant_idx_cb: 0,
            quant_idx_cr: 0,
            x_idx: 0,
            y_idx: 0,
            y_data: vec![],
            cb_data: vec![],
            cr_data: vec![],
        };
        let d = roundtrip(&t);
        assert_eq!(d, t);
        assert_eq!(t.size(), RFX_TILE_FIXED_PREFIX_SIZE);
    }

    #[test]
    fn rfx_tile_wire_byte_layout() {
        let t = RfxTileWire {
            quant_idx_y: 0x11,
            quant_idx_cb: 0x22,
            quant_idx_cr: 0x33,
            x_idx: 0x0102,
            y_idx: 0x0304,
            y_data: vec![0xAA; 2],
            cb_data: vec![0xBB; 3],
            cr_data: vec![0xCC; 1],
        };
        let mut buf = vec![0u8; t.size()];
        t.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // header: blockType CBT_TILE = 0xCAC3
        assert_eq!(&buf[..2], &[0xC3, 0xCA]);
        // blockLen = 19 + 2 + 3 + 1 = 25 = 0x19
        assert_eq!(&buf[2..6], &[0x19, 0x00, 0x00, 0x00]);
        // quant indices
        assert_eq!(&buf[6..9], &[0x11, 0x22, 0x33]);
        // xIdx, yIdx LE
        assert_eq!(&buf[9..11], &[0x02, 0x01]);
        assert_eq!(&buf[11..13], &[0x04, 0x03]);
        // YLen=2, CbLen=3, CrLen=1
        assert_eq!(&buf[13..15], &[0x02, 0x00]);
        assert_eq!(&buf[15..17], &[0x03, 0x00]);
        assert_eq!(&buf[17..19], &[0x01, 0x00]);
        // payload
        assert_eq!(&buf[19..21], &[0xAA, 0xAA]);
        assert_eq!(&buf[21..24], &[0xBB, 0xBB, 0xBB]);
        assert_eq!(&buf[24..25], &[0xCC]);
    }

    #[test]
    fn rfx_tile_wire_decode_rejects_blocklen_mismatch() {
        let t = sample_tile(0, 0, 0, 16);
        let mut buf = vec![0u8; t.size()];
        t.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // blockLen at bytes 2..6 -- claim 0xFF.
        buf[2] = 0xFF;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxTileWire::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_tile_wire_decode_rejects_wrong_block_type() {
        let t = sample_tile(0, 0, 0, 16);
        let mut buf = vec![0u8; t.size()];
        t.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // CBT_REGION (0xCAC1) instead of CBT_TILE (0xCAC3) -- low byte differs.
        buf[0] = 0xC1;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxTileWire::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_tileset_single_quant_single_tile_roundtrip() {
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals: vec![sample_quant()],
            tiles: vec![sample_tile(0, 0, 0, 64)],
        };
        let d = roundtrip(&ts);
        assert_eq!(d, ts);
        // 22 + 1*5 + (19 + 64*3) = 22 + 5 + 211 = 238
        assert_eq!(ts.size(), 22 + 5 + 19 + 64 * 3);
    }

    #[test]
    fn rfx_tileset_multi_quant_multi_tile_roundtrip() {
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr1),
            quant_vals: vec![sample_quant(), sample_quant(), sample_quant()],
            tiles: vec![
                sample_tile(0, 0, 0, 32),
                sample_tile(1, 1, 0, 48),
                sample_tile(2, 0, 1, 16),
                sample_tile(2, 1, 1, 24),
            ],
        };
        let d = roundtrip(&ts);
        assert_eq!(d, ts);
    }

    #[test]
    fn rfx_tileset_zero_tiles_roundtrip() {
        // numTiles = 0, tilesDataSize = 0 -- wire-legal even if useless.
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals: vec![],
            tiles: vec![],
        };
        let d = roundtrip(&ts);
        assert_eq!(d, ts);
        assert_eq!(ts.size(), 22);
    }

    #[test]
    fn rfx_tileset_byte_layout_constants() {
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals: vec![],
            tiles: vec![],
        };
        let mut buf = vec![0u8; ts.size()];
        ts.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // header: WBT_EXTENSION = 0xCCC7
        assert_eq!(&buf[..2], &[0xC7, 0xCC]);
        // blockLen = 22
        assert_eq!(&buf[2..6], &[0x16, 0x00, 0x00, 0x00]);
        assert_eq!(buf[6], CODEC_ID);
        assert_eq!(buf[7], CHANNEL_ID_DATA);
        // subtype CBT_TILESET = 0xCAC2
        assert_eq!(&buf[8..10], &[0xC2, 0xCA]);
        // idx = 0
        assert_eq!(&buf[10..12], &[0x00, 0x00]);
        // properties = pack_tileset(image, RLGR3) = 0x5055
        assert_eq!(&buf[12..14], &[0x55, 0x50]);
        // numQuant = 0
        assert_eq!(buf[14], 0x00);
        // tileSize = 0x40
        assert_eq!(buf[15], TILESET_TILE_SIZE);
        // numTiles = 0 LE
        assert_eq!(&buf[16..18], &[0x00, 0x00]);
        // tilesDataSize = 0 LE u32
        assert_eq!(&buf[18..22], &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn rfx_tileset_encode_rejects_quant_idx_out_of_range() {
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals: vec![sample_quant()],
            tiles: vec![sample_tile(5, 0, 0, 16)], // idx 5 with only 1 quant entry
        };
        let mut buf = vec![0u8; ts.size()];
        assert!(ts.encode(&mut WriteCursor::new(&mut buf)).is_err());
    }

    #[test]
    fn rfx_tileset_decode_rejects_wrong_subtype() {
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals: vec![],
            tiles: vec![],
        };
        let mut buf = vec![0u8; ts.size()];
        ts.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // subtype is at bytes 8..10; corrupt to 0xCAC1 (CBT_REGION).
        buf[8] = 0xC1;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxTileSet::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_tileset_decode_rejects_wrong_idx() {
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals: vec![],
            tiles: vec![],
        };
        let mut buf = vec![0u8; ts.size()];
        ts.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // idx at bytes 10..12; corrupt to 1.
        buf[10] = 0x01;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxTileSet::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_tileset_decode_rejects_wrong_tile_size() {
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals: vec![],
            tiles: vec![],
        };
        let mut buf = vec![0u8; ts.size()];
        ts.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // tileSize at byte 15; corrupt to 0x80.
        buf[15] = 0x80;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxTileSet::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_tileset_decode_rejects_wrong_block_type() {
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals: vec![],
            tiles: vec![],
        };
        let mut buf = vec![0u8; ts.size()];
        ts.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[0] = 0xC0; // -> WBT_SYNC
        let mut src = ReadCursor::new(&buf);
        assert!(RfxTileSet::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_tileset_decode_rejects_wrong_codec_id() {
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals: vec![],
            tiles: vec![],
        };
        let mut buf = vec![0u8; ts.size()];
        ts.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[6] = 0x02;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxTileSet::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_tileset_decode_rejects_wrong_channel_id() {
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals: vec![],
            tiles: vec![],
        };
        let mut buf = vec![0u8; ts.size()];
        ts.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[7] = CHANNEL_ID_CONTEXT;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxTileSet::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_tileset_decode_rejects_blocklen_mismatch() {
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals: vec![sample_quant()],
            tiles: vec![sample_tile(0, 0, 0, 16)],
        };
        let mut buf = vec![0u8; ts.size()];
        ts.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[2] = 0xFF;
        let mut src = ReadCursor::new(&buf);
        assert!(RfxTileSet::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_tileset_encode_at_max_num_quant() {
        // 255 quant entries -- u8 upper boundary; tile uses index 254
        // (highest valid).
        let quant_vals = (0..255).map(|_| sample_quant()).collect::<Vec<_>>();
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals,
            tiles: vec![RfxTileWire {
                quant_idx_y: 254,
                quant_idx_cb: 254,
                quant_idx_cr: 254,
                x_idx: 0,
                y_idx: 0,
                y_data: vec![],
                cb_data: vec![],
                cr_data: vec![],
            }],
        };
        let d = roundtrip(&ts);
        assert_eq!(d.quant_vals.len(), 255);
        assert_eq!(d.tiles[0].quant_idx_y, 254);
        // 22 + 255*5 + 19 = 22 + 1275 + 19 = 1316
        assert_eq!(ts.size(), 22 + 255 * 5 + 19);
    }

    #[test]
    fn rfx_tileset_encode_rejects_more_than_u8_max_quant_entries() {
        let quant_vals = (0..256).map(|_| sample_quant()).collect::<Vec<_>>();
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals,
            tiles: vec![],
        };
        let mut buf = vec![0u8; ts.size()];
        assert!(ts.encode(&mut WriteCursor::new(&mut buf)).is_err());
    }

    #[test]
    fn rfx_tileset_encode_rejects_more_than_u16_max_tiles() {
        // 65536 tiles -- exceeds u16 numTiles cap.
        let tiles = (0..65_536_usize)
            .map(|_| RfxTileWire {
                quant_idx_y: 0,
                quant_idx_cb: 0,
                quant_idx_cr: 0,
                x_idx: 0,
                y_idx: 0,
                y_data: vec![],
                cb_data: vec![],
                cr_data: vec![],
            })
            .collect::<Vec<_>>();
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals: vec![sample_quant()],
            tiles,
        };
        let mut buf = vec![0u8; ts.size()];
        assert!(ts.encode(&mut WriteCursor::new(&mut buf)).is_err());
    }

    #[test]
    fn rfx_tileset_decode_rejects_tiles_data_size_mismatch() {
        let ts = RfxTileSet {
            properties: RfxProperties::image(RlgrMode::Rlgr3),
            quant_vals: vec![sample_quant()],
            tiles: vec![sample_tile(0, 0, 0, 16)],
        };
        let mut buf = vec![0u8; ts.size()];
        ts.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // tilesDataSize is at bytes 18..22; lower it by 1 -- decoder must
        // detect blockLen vs computed size mismatch.
        if buf[18] > 0 {
            buf[18] -= 1;
        } else {
            buf[18] = 1;
        }
        let mut src = ReadCursor::new(&buf);
        assert!(RfxTileSet::decode(&mut src).is_err());
    }

    #[test]
    fn rfx_region_decode_rejects_blocklen_mismatch() {
        let r = RfxRegion {
            rects: vec![RfxRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            }],
        };
        let mut buf = vec![0u8; r.size()];
        r.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf[2] = 0xFF; // corrupt blockLen
        let mut src = ReadCursor::new(&buf);
        assert!(RfxRegion::decode(&mut src).is_err());
    }
}
