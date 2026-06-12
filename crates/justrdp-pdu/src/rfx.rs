//! RemoteFX message-set parser (MS-RDPRFX 2.2.2) — the `TS_RFX_*` block stream carried in an
//! EGFX WireToSurface1 payload when the server selects `CODECID_CAVIDEO` (issue #58). This
//! module owns bytes→types only: block framing, the eight message bodies (Sync, CodecVersions,
//! Channels, Context, FrameBegin/End, Region, TileSet with its Quant and Tile records), and
//! their structural validation. The pixel math — RLGR entropy decode, dequantization, inverse
//! DWT, YCbCr→RGB — lives in `justrdp-codecs` (ADR-0003 phase-2, ADR-0007 verification).
//!
//! One payload can carry several blocks back to back ([`decode_all`] walks the chain). A
//! stream starts with header messages (Sync → CodecVersions → Channels → Context) and then
//! repeats frames (FrameBegin → Region → TileSet → FrameEnd); servers send the headers only
//! once per stream, so a parsed message list may legitimately start mid-frame.

use crate::cursor::ReadCursor;
use crate::error::DecodeError;

/// `WBT_SYNC` — TS_RFX_SYNC block type.
pub const BLOCK_SYNC: u16 = 0xCCC0;
/// `WBT_CODEC_VERSIONS` — TS_RFX_CODEC_VERSIONS block type.
pub const BLOCK_CODEC_VERSIONS: u16 = 0xCCC1;
/// `WBT_CHANNELS` — TS_RFX_CHANNELS block type.
pub const BLOCK_CHANNELS: u16 = 0xCCC2;
/// `WBT_CONTEXT` — TS_RFX_CONTEXT block type (codec-channel framed).
pub const BLOCK_CONTEXT: u16 = 0xCCC3;
/// `WBT_FRAME_BEGIN` — TS_RFX_FRAME_BEGIN block type (codec-channel framed).
pub const BLOCK_FRAME_BEGIN: u16 = 0xCCC4;
/// `WBT_FRAME_END` — TS_RFX_FRAME_END block type (codec-channel framed).
pub const BLOCK_FRAME_END: u16 = 0xCCC5;
/// `WBT_REGION` — TS_RFX_REGION block type (codec-channel framed).
pub const BLOCK_REGION: u16 = 0xCCC6;
/// `WBT_EXTENSION` — carries TS_RFX_TILESET (codec-channel framed).
pub const BLOCK_TILESET: u16 = 0xCCC7;
/// `CBT_TILE` — one TS_RFX_TILE inside a tileset.
pub const BLOCK_TILE: u16 = 0xCAC3;

/// TS_RFX_SYNC `magic`.
pub const SYNC_MAGIC: u32 = 0xCACC_ACCA;
/// TS_RFX_SYNC / TS_RFX_CODEC_VERSIONT `version` — WF_VERSION_1_0.
pub const SYNC_VERSION: u16 = 0x0100;
/// The fixed RemoteFX tile edge in pixels (`CT_TILE_64x64`).
pub const TILE_DIM: u16 = 64;

/// The `properties.et` entropy variant a stream's tiles are coded with (MS-RDPRFX 2.2.2.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyAlgorithm {
    /// `CLW_ENTROPY_RLGR1` (0x01).
    Rlgr1,
    /// `CLW_ENTROPY_RLGR3` (0x04).
    Rlgr3,
}

impl EntropyAlgorithm {
    fn from_bits(bits: u16) -> Result<Self, DecodeError> {
        match bits {
            0x01 => Ok(EntropyAlgorithm::Rlgr1),
            0x04 => Ok(EntropyAlgorithm::Rlgr3),
            _ => Err(invalid("properties.et", "unknown entropy algorithm")),
        }
    }
}

/// One TS_RFX_CODEC_QUANT (2.2.2.1.5): a 4-bit quantization exponent per DWT subband.
/// Field order matches the wire nibble order (low nibble first within each byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quant {
    /// Level-3 lowpass.
    pub ll3: u8,
    /// Level-3 horizontal highpass.
    pub lh3: u8,
    /// Level-3 vertical highpass.
    pub hl3: u8,
    /// Level-3 diagonal highpass.
    pub hh3: u8,
    /// Level-2 horizontal highpass.
    pub lh2: u8,
    /// Level-2 vertical highpass.
    pub hl2: u8,
    /// Level-2 diagonal highpass.
    pub hh2: u8,
    /// Level-1 horizontal highpass.
    pub lh1: u8,
    /// Level-1 vertical highpass.
    pub hl1: u8,
    /// Level-1 diagonal highpass.
    pub hh1: u8,
}

impl Quant {
    fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let b0 = cur.read_u8()?;
        let b1 = cur.read_u8()?;
        let b2 = cur.read_u8()?;
        let b3 = cur.read_u8()?;
        let b4 = cur.read_u8()?;
        Ok(Self {
            ll3: b0 & 0x0F,
            lh3: b0 >> 4,
            hl3: b1 & 0x0F,
            hh3: b1 >> 4,
            lh2: b2 & 0x0F,
            hl2: b2 >> 4,
            hh2: b3 & 0x0F,
            lh1: b3 >> 4,
            hl1: b4 & 0x0F,
            hh1: b4 >> 4,
        })
    }
}

/// One TS_RFX_RECT (2.2.2.1.6): a region clip rectangle in pixels, relative to the frame
/// origin (the WireToSurface1 destination rectangle's top-left).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfxRect {
    /// Left edge.
    pub x: u16,
    /// Top edge.
    pub y: u16,
    /// Width in pixels.
    pub width: u16,
    /// Height in pixels.
    pub height: u16,
}

/// One TS_RFX_CHANNELT (2.2.2.1.3) entry from TS_RFX_CHANNELS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfxChannel {
    /// Channel width in pixels.
    pub width: i16,
    /// Channel height in pixels.
    pub height: i16,
}

/// One TS_RFX_TILE (2.2.2.3.4.1): per-component quant indices, the tile's grid position
/// (multiply by [`TILE_DIM`] for pixels), and the three RLGR-coded component streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tile<'a> {
    /// Index into the tileset's quant table for the luma component.
    pub quant_idx_y: u8,
    /// Index into the tileset's quant table for the blue-difference chroma component.
    pub quant_idx_cb: u8,
    /// Index into the tileset's quant table for the red-difference chroma component.
    pub quant_idx_cr: u8,
    /// Tile column in the 64×64 grid (pixel x = `x_idx * 64`).
    pub x_idx: u16,
    /// Tile row in the 64×64 grid (pixel y = `y_idx * 64`).
    pub y_idx: u16,
    /// RLGR-coded luma coefficients.
    pub y_data: &'a [u8],
    /// RLGR-coded Cb coefficients.
    pub cb_data: &'a [u8],
    /// RLGR-coded Cr coefficients.
    pub cr_data: &'a [u8],
}

/// One TS_RFX_TILESET (2.2.2.3.4): the entropy variant, the quant table, and the tiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TileSet<'a> {
    /// The entropy algorithm coding this tileset's tiles.
    pub entropy: EntropyAlgorithm,
    /// The quant table tiles index into (every tile index is validated against its length).
    pub quants: Vec<Quant>,
    /// The coded tiles.
    pub tiles: Vec<Tile<'a>>,
}

/// One parsed TS_RFX block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RfxMessage<'a> {
    /// TS_RFX_SYNC — stream start marker (magic/version validated).
    Sync,
    /// TS_RFX_CODEC_VERSIONS — advertised codec version (validated to WF_VERSION_1_0).
    CodecVersions,
    /// TS_RFX_CHANNELS — the channel dimension list.
    Channels(Vec<RfxChannel>),
    /// TS_RFX_CONTEXT — stream-wide coding parameters.
    Context {
        /// `flags & CODEC_MODE`: true = image mode (each frame standalone), false = the
        /// legacy video mode (inter-frame diffing) justrdp does not decode (issue #58 scope).
        image_mode: bool,
        /// The entropy algorithm declared stream-wide (each tileset re-declares it).
        entropy: EntropyAlgorithm,
    },
    /// TS_RFX_FRAME_BEGIN.
    FrameBegin {
        /// Server frame counter.
        index: u32,
        /// Number of TS_RFX_REGION messages in the frame.
        regions: i16,
    },
    /// TS_RFX_FRAME_END.
    FrameEnd,
    /// TS_RFX_REGION — the clip rectangles tiles are masked to.
    Region(Vec<RfxRect>),
    /// TS_RFX_TILESET — the coded tiles.
    TileSet(TileSet<'a>),
}

fn invalid(field: &'static str, reason: &'static str) -> DecodeError {
    DecodeError::InvalidField { field, reason }
}

/// Walk every TS_RFX block in `data` (a complete WireToSurface1 CAVIDEO payload) into typed
/// messages. Unknown block types are skipped by their declared length (forward compatibility);
/// malformed framing or field values are a typed error, never a panic.
pub fn decode_all(data: &[u8]) -> Result<Vec<RfxMessage<'_>>, DecodeError> {
    let mut cur = ReadCursor::new(data, "TS_RFX block stream");
    let mut messages = Vec::new();
    while cur.remaining() > 0 {
        let block_type = cur.read_u16_le()?;
        let block_len = cur.read_u32_le()? as usize;
        // blockLen counts the whole block, header included (TS_RFX_BLOCKT 2.2.2.1.1).
        let mut consumed = 6usize;
        if is_codec_channel(block_type) {
            let codec_id = cur.read_u8()?;
            if codec_id != 1 {
                return Err(invalid("TS_RFX_CODEC_CHANNELT.codecId", "must be 1"));
            }
            let channel_id = cur.read_u8()?;
            let expected = if block_type == BLOCK_CONTEXT {
                0xFF
            } else {
                0x00
            };
            if channel_id != expected {
                return Err(invalid(
                    "TS_RFX_CODEC_CHANNELT.channelId",
                    "0xFF for context, 0x00 otherwise",
                ));
            }
            consumed += 2;
        }
        let body_len = block_len
            .checked_sub(consumed)
            .ok_or(invalid("TS_RFX_BLOCKT.blockLen", "shorter than its header"))?;
        let body = cur.read_slice(body_len)?;
        let mut body = ReadCursor::new(body, "TS_RFX block body");
        match block_type {
            BLOCK_SYNC => messages.push(decode_sync(&mut body)?),
            BLOCK_CODEC_VERSIONS => messages.push(decode_codec_versions(&mut body)?),
            BLOCK_CHANNELS => messages.push(decode_channels(&mut body)?),
            BLOCK_CONTEXT => messages.push(decode_context(&mut body)?),
            BLOCK_FRAME_BEGIN => messages.push(RfxMessage::FrameBegin {
                index: body.read_u32_le()?,
                regions: body.read_u16_le()? as i16,
            }),
            BLOCK_FRAME_END => messages.push(RfxMessage::FrameEnd),
            BLOCK_REGION => messages.push(decode_region(&mut body)?),
            BLOCK_TILESET => messages.push(decode_tileset(&mut body)?),
            // Unknown (including the capability blocks of the legacy surface-bits path):
            // already skipped by the length-framed read above.
            _ => {}
        }
    }
    Ok(messages)
}

fn is_codec_channel(block_type: u16) -> bool {
    matches!(
        block_type,
        BLOCK_CONTEXT | BLOCK_FRAME_BEGIN | BLOCK_FRAME_END | BLOCK_REGION | BLOCK_TILESET
    )
}

fn decode_sync(cur: &mut ReadCursor<'_>) -> Result<RfxMessage<'static>, DecodeError> {
    if cur.read_u32_le()? != SYNC_MAGIC {
        return Err(invalid("TS_RFX_SYNC.magic", "expected 0xCACCACCA"));
    }
    if cur.read_u16_le()? != SYNC_VERSION {
        return Err(invalid("TS_RFX_SYNC.version", "expected WF_VERSION_1_0"));
    }
    Ok(RfxMessage::Sync)
}

fn decode_codec_versions(cur: &mut ReadCursor<'_>) -> Result<RfxMessage<'static>, DecodeError> {
    if cur.read_u8()? != 1 {
        return Err(invalid("TS_RFX_CODEC_VERSIONS.numCodecs", "must be 1"));
    }
    if cur.read_u8()? != 1 {
        return Err(invalid("TS_RFX_CODEC_VERSIONT.codecId", "must be 1"));
    }
    if cur.read_u16_le()? != SYNC_VERSION {
        return Err(invalid(
            "TS_RFX_CODEC_VERSIONT.version",
            "expected WF_VERSION_1_0",
        ));
    }
    Ok(RfxMessage::CodecVersions)
}

fn decode_channels(cur: &mut ReadCursor<'_>) -> Result<RfxMessage<'static>, DecodeError> {
    let count = usize::from(cur.read_u8()?);
    let mut channels = Vec::with_capacity(count.min(16));
    for _ in 0..count {
        if cur.read_u8()? != 0 {
            return Err(invalid("TS_RFX_CHANNELT.channelId", "must be 0"));
        }
        channels.push(RfxChannel {
            width: cur.read_u16_le()? as i16,
            height: cur.read_u16_le()? as i16,
        });
    }
    Ok(RfxMessage::Channels(channels))
}

fn decode_context(cur: &mut ReadCursor<'_>) -> Result<RfxMessage<'static>, DecodeError> {
    if cur.read_u8()? != 0 {
        return Err(invalid("TS_RFX_CONTEXT.ctxId", "must be 0"));
    }
    if cur.read_u16_le()? != TILE_DIM {
        return Err(invalid(
            "TS_RFX_CONTEXT.tileSize",
            "must be 64 (CT_TILE_64x64)",
        ));
    }
    let properties = cur.read_u16_le()?;
    // properties: flags(0..3) | cct(3..5) | xft(5..9) | et(9..13) | qt(13..15) | r(15).
    let image_mode = properties & 0x0002 != 0; // CODEC_MODE flag
    if (properties >> 3) & 0x3 != 1 {
        return Err(invalid("TS_RFX_CONTEXT.properties.cct", "must be ICT (1)"));
    }
    if (properties >> 5) & 0xF != 1 {
        return Err(invalid(
            "TS_RFX_CONTEXT.properties.xft",
            "must be DWT 5/3 (1)",
        ));
    }
    let entropy = EntropyAlgorithm::from_bits((properties >> 9) & 0xF)?;
    if (properties >> 13) & 0x3 != 1 {
        return Err(invalid(
            "TS_RFX_CONTEXT.properties.qt",
            "must be scalar (1)",
        ));
    }
    Ok(RfxMessage::Context {
        image_mode,
        entropy,
    })
}

fn decode_region(cur: &mut ReadCursor<'_>) -> Result<RfxMessage<'static>, DecodeError> {
    let region_flags = cur.read_u8()?;
    if region_flags & 0x01 == 0 {
        return Err(invalid("TS_RFX_REGION.regionFlags", "lrf bit must be set"));
    }
    let count = usize::from(cur.read_u16_le()?);
    if cur.remaining() < count * 8 {
        return Err(invalid("TS_RFX_REGION.numRects", "more rects than bytes"));
    }
    let mut rects = Vec::with_capacity(count);
    for _ in 0..count {
        rects.push(RfxRect {
            x: cur.read_u16_le()?,
            y: cur.read_u16_le()?,
            width: cur.read_u16_le()?,
            height: cur.read_u16_le()?,
        });
    }
    if cur.read_u16_le()? != 0xCAC1 {
        return Err(invalid("TS_RFX_REGION.regionType", "must be CBT_REGION"));
    }
    if cur.read_u16_le()? != 1 {
        return Err(invalid("TS_RFX_REGION.numTilesets", "must be 1"));
    }
    Ok(RfxMessage::Region(rects))
}

fn decode_tileset<'a>(cur: &mut ReadCursor<'a>) -> Result<RfxMessage<'a>, DecodeError> {
    if cur.read_u16_le()? != 0xCAC2 {
        return Err(invalid("TS_RFX_TILESET.subtype", "must be CBT_TILESET"));
    }
    if cur.read_u16_le()? != 0 {
        return Err(invalid("TS_RFX_TILESET.idx", "must be 0"));
    }
    let properties = cur.read_u16_le()?;
    // properties: lt(0) | flags(1..4, decoder MUST ignore) | cct(4..6) | xft(6..10) |
    // et(10..14) | qt(14..16).
    if properties & 0x01 == 0 {
        return Err(invalid(
            "TS_RFX_TILESET.properties.lt",
            "must be the last tileset",
        ));
    }
    if (properties >> 4) & 0x3 != 1 {
        return Err(invalid("TS_RFX_TILESET.properties.cct", "must be ICT (1)"));
    }
    if (properties >> 6) & 0xF != 1 {
        return Err(invalid(
            "TS_RFX_TILESET.properties.xft",
            "must be DWT 5/3 (1)",
        ));
    }
    let entropy = EntropyAlgorithm::from_bits((properties >> 10) & 0xF)?;
    if (properties >> 14) & 0x3 != 1 {
        return Err(invalid(
            "TS_RFX_TILESET.properties.qt",
            "must be scalar (1)",
        ));
    }
    let num_quant = usize::from(cur.read_u8()?);
    if u16::from(cur.read_u8()?) != TILE_DIM {
        return Err(invalid(
            "TS_RFX_TILESET.tileSize",
            "must be 64 (CT_TILE_64x64)",
        ));
    }
    let num_tiles = usize::from(cur.read_u16_le()?);
    let _tiles_data_size = cur.read_u32_le()?;

    let mut quants = Vec::with_capacity(num_quant);
    for _ in 0..num_quant {
        quants.push(Quant::decode(cur)?);
    }

    let mut tiles = Vec::with_capacity(num_tiles.min(1024));
    for _ in 0..num_tiles {
        if cur.read_u16_le()? != BLOCK_TILE {
            return Err(invalid("TS_RFX_TILE.blockType", "must be CBT_TILE"));
        }
        let tile_len = cur.read_u32_le()? as usize;
        let body_len = tile_len
            .checked_sub(6)
            .ok_or(invalid("TS_RFX_TILE.blockLen", "shorter than its header"))?;
        let body = cur.read_slice(body_len)?;
        let mut t = ReadCursor::new(body, "TS_RFX_TILE body");
        let quant_idx_y = t.read_u8()?;
        let quant_idx_cb = t.read_u8()?;
        let quant_idx_cr = t.read_u8()?;
        for idx in [quant_idx_y, quant_idx_cb, quant_idx_cr] {
            if usize::from(idx) >= num_quant {
                return Err(invalid(
                    "TS_RFX_TILE.quantIdx",
                    "index beyond the quant table",
                ));
            }
        }
        let x_idx = t.read_u16_le()?;
        let y_idx = t.read_u16_le()?;
        let y_len = usize::from(t.read_u16_le()?);
        let cb_len = usize::from(t.read_u16_le()?);
        let cr_len = usize::from(t.read_u16_le()?);
        tiles.push(Tile {
            quant_idx_y,
            quant_idx_cb,
            quant_idx_cr,
            x_idx,
            y_idx,
            y_data: t.read_slice(y_len)?,
            cb_data: t.read_slice(cb_len)?,
            cr_data: t.read_slice(cr_len)?,
        });
    }
    Ok(RfxMessage::TileSet(TileSet {
        entropy,
        quants,
        tiles,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append one block header (and the codec-channel header where the type requires it).
    fn push_block(out: &mut Vec<u8>, block_type: u16, body: &[u8]) {
        let channel = is_codec_channel(block_type);
        let len = 6 + if channel { 2 } else { 0 } + body.len();
        out.extend_from_slice(&block_type.to_le_bytes());
        out.extend_from_slice(&(len as u32).to_le_bytes());
        if channel {
            out.push(1);
            out.push(if block_type == BLOCK_CONTEXT {
                0xFF
            } else {
                0x00
            });
        }
        out.extend_from_slice(body);
    }

    fn sync_body() -> Vec<u8> {
        let mut b = SYNC_MAGIC.to_le_bytes().to_vec();
        b.extend_from_slice(&SYNC_VERSION.to_le_bytes());
        b
    }

    fn context_body(image_mode: bool, entropy_bits: u16) -> Vec<u8> {
        let flags: u16 = if image_mode { 0x02 } else { 0x00 };
        let properties: u16 = flags | (1 << 3) | (1 << 5) | (entropy_bits << 9) | (1 << 13);
        let mut b = vec![0u8]; // ctxId
        b.extend_from_slice(&64u16.to_le_bytes());
        b.extend_from_slice(&properties.to_le_bytes());
        b
    }

    fn tileset_body(entropy_bits: u16, quants: &[[u8; 5]], tiles: &[Vec<u8>]) -> Vec<u8> {
        let properties: u16 = 0x01 | (1 << 4) | (1 << 6) | (entropy_bits << 10) | (1 << 14);
        let mut b = Vec::new();
        b.extend_from_slice(&0xCAC2u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&properties.to_le_bytes());
        b.push(quants.len() as u8);
        b.push(64);
        b.extend_from_slice(&(tiles.len() as u16).to_le_bytes());
        let data_size: usize = tiles.iter().map(Vec::len).sum();
        b.extend_from_slice(&(data_size as u32).to_le_bytes());
        for q in quants {
            b.extend_from_slice(q);
        }
        for t in tiles {
            b.extend_from_slice(t);
        }
        b
    }

    fn tile_block(
        quant_idx: u8,
        x_idx: u16,
        y_idx: u16,
        y: &[u8],
        cb: &[u8],
        cr: &[u8],
    ) -> Vec<u8> {
        let body_len = 13 + y.len() + cb.len() + cr.len();
        let mut t = Vec::new();
        t.extend_from_slice(&BLOCK_TILE.to_le_bytes());
        t.extend_from_slice(&((6 + body_len) as u32).to_le_bytes());
        t.push(quant_idx);
        t.push(quant_idx);
        t.push(quant_idx);
        t.extend_from_slice(&x_idx.to_le_bytes());
        t.extend_from_slice(&y_idx.to_le_bytes());
        t.extend_from_slice(&(y.len() as u16).to_le_bytes());
        t.extend_from_slice(&(cb.len() as u16).to_le_bytes());
        t.extend_from_slice(&(cr.len() as u16).to_le_bytes());
        t.extend_from_slice(y);
        t.extend_from_slice(cb);
        t.extend_from_slice(cr);
        t
    }

    #[test]
    fn full_header_and_frame_stream_parses_in_order() {
        let mut data = Vec::new();
        push_block(&mut data, BLOCK_SYNC, &sync_body());
        push_block(&mut data, BLOCK_CODEC_VERSIONS, &[1, 1, 0x00, 0x01]);
        // One 640×480 channel.
        let mut channels = vec![1u8, 0];
        channels.extend_from_slice(&640u16.to_le_bytes());
        channels.extend_from_slice(&480u16.to_le_bytes());
        push_block(&mut data, BLOCK_CHANNELS, &channels);
        push_block(&mut data, BLOCK_CONTEXT, &context_body(true, 0x01));
        let mut frame_begin = 7u32.to_le_bytes().to_vec();
        frame_begin.extend_from_slice(&1u16.to_le_bytes());
        push_block(&mut data, BLOCK_FRAME_BEGIN, &frame_begin);
        // Region: one 64×64 rect at the origin.
        let mut region = vec![0x01u8];
        region.extend_from_slice(&1u16.to_le_bytes());
        for v in [0u16, 0, 64, 64] {
            region.extend_from_slice(&v.to_le_bytes());
        }
        region.extend_from_slice(&0xCAC1u16.to_le_bytes());
        region.extend_from_slice(&1u16.to_le_bytes());
        push_block(&mut data, BLOCK_REGION, &region);
        let tile = tile_block(0, 0, 0, &[0xAA; 3], &[0xBB; 2], &[0xCC; 4]);
        push_block(
            &mut data,
            BLOCK_TILESET,
            &tileset_body(0x04, &[[0x66, 0x66, 0x77, 0x88, 0x98]], &[tile]),
        );
        push_block(&mut data, BLOCK_FRAME_END, &[]);

        let messages = decode_all(&data).expect("valid stream");
        assert_eq!(messages.len(), 8);
        assert_eq!(messages[0], RfxMessage::Sync);
        assert_eq!(messages[1], RfxMessage::CodecVersions);
        assert_eq!(
            messages[2],
            RfxMessage::Channels(vec![RfxChannel {
                width: 640,
                height: 480
            }])
        );
        assert_eq!(
            messages[3],
            RfxMessage::Context {
                image_mode: true,
                entropy: EntropyAlgorithm::Rlgr1
            }
        );
        assert_eq!(
            messages[4],
            RfxMessage::FrameBegin {
                index: 7,
                regions: 1
            }
        );
        assert_eq!(
            messages[5],
            RfxMessage::Region(vec![RfxRect {
                x: 0,
                y: 0,
                width: 64,
                height: 64
            }])
        );
        let RfxMessage::TileSet(ts) = &messages[6] else {
            panic!("expected a tileset");
        };
        assert_eq!(ts.entropy, EntropyAlgorithm::Rlgr3);
        assert_eq!(
            ts.quants,
            vec![Quant {
                ll3: 6,
                lh3: 6,
                hl3: 6,
                hh3: 6,
                lh2: 7,
                hl2: 7,
                hh2: 8,
                lh1: 8,
                hl1: 8,
                hh1: 9
            }]
        );
        assert_eq!(ts.tiles.len(), 1);
        assert_eq!(ts.tiles[0].y_data, &[0xAA; 3]);
        assert_eq!(ts.tiles[0].cb_data, &[0xBB; 2]);
        assert_eq!(ts.tiles[0].cr_data, &[0xCC; 4]);
        assert_eq!(messages[7], RfxMessage::FrameEnd);
    }

    #[test]
    fn unknown_block_types_are_skipped_by_length() {
        let mut data = Vec::new();
        push_block(&mut data, 0xCBC0, &[0xDE, 0xAD]); // legacy caps block
        push_block(&mut data, BLOCK_SYNC, &sync_body());
        let messages = decode_all(&data).expect("unknown blocks skip");
        assert_eq!(messages, vec![RfxMessage::Sync]);
    }

    #[test]
    fn malformed_streams_yield_typed_errors_not_panics() {
        // Truncated header.
        assert!(decode_all(&[0xC0]).is_err());
        // Block length shorter than its own header.
        let mut data = BLOCK_SYNC.to_le_bytes().to_vec();
        data.extend_from_slice(&2u32.to_le_bytes());
        assert!(decode_all(&data).is_err());
        // Block length longer than the buffer.
        let mut data = BLOCK_SYNC.to_le_bytes().to_vec();
        data.extend_from_slice(&100u32.to_le_bytes());
        assert!(decode_all(&data).is_err());
        // Bad sync magic.
        let mut data = Vec::new();
        let mut body = 0xDEADBEEFu32.to_le_bytes().to_vec();
        body.extend_from_slice(&SYNC_VERSION.to_le_bytes());
        push_block(&mut data, BLOCK_SYNC, &body);
        assert!(decode_all(&data).is_err());
        // Context with video mode parses (the codec layer rejects it, not the parser).
        let mut data = Vec::new();
        push_block(&mut data, BLOCK_CONTEXT, &context_body(false, 0x01));
        assert_eq!(
            decode_all(&data).expect("video-mode context parses"),
            vec![RfxMessage::Context {
                image_mode: false,
                entropy: EntropyAlgorithm::Rlgr1
            }]
        );
        // Unknown entropy bits.
        let mut data = Vec::new();
        push_block(&mut data, BLOCK_CONTEXT, &context_body(true, 0x02));
        assert!(decode_all(&data).is_err());
        // Tile quant index beyond the table.
        let tile = tile_block(3, 0, 0, &[0xAA], &[0xBB], &[0xCC]);
        let mut data = Vec::new();
        push_block(
            &mut data,
            BLOCK_TILESET,
            &tileset_body(0x01, &[[0x66, 0x66, 0x77, 0x88, 0x98]], &[tile]),
        );
        assert!(decode_all(&data).is_err());
        // Tile data lengths overrunning the tileset body.
        let mut bad_tile = tile_block(0, 0, 0, &[], &[], &[]);
        // Claim 100 luma bytes that are not there (offset 13 = YLen within the tile body).
        bad_tile[13] = 100;
        let mut data = Vec::new();
        push_block(
            &mut data,
            BLOCK_TILESET,
            &tileset_body(0x01, &[[0x66, 0x66, 0x77, 0x88, 0x98]], &[bad_tile]),
        );
        assert!(decode_all(&data).is_err());
    }
}
