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
//! This file is staged across §11.2b-2 commits; this commit lands the
//! handshake set (Sync / CodecVersions / Channels). Subsequent commits
//! add Context, FrameBegin/FrameEnd/Region, TileSet/Tile, and the
//! `RfxFrameEncoder` state machine on top.

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

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
}
