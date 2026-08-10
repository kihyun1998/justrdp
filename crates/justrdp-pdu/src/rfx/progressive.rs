//! RemoteFX Progressive block-stream parser ([MS-RDPEGFX] 2.2.4, the RemoteFX Progressive
//! Codec Extension) — the `RFX_PROGRESSIVE_*` blocks carried in an EGFX **WireToSurface2**
//! payload when the server selects `RDPGFX_CODECID_CAPROGRESSIVE` (epic #158, slice 1). This
//! module owns bytes→types only: block framing, the five stream-level blocks, the region's
//! quantization tables, and the three tile records nested inside it. The pixel math — SRL
//! entropy decode, sub-band diffing, multi-pass coefficient refinement, dequantization,
//! inverse DWT, ICT — lives in `justrdp-codecs` (epic #158 slices 2–5).
//!
//! **The block-type numbers collide with the sibling WireToSurface1 parser's.** Both streams
//! number their blocks `0xCCCx` and only two of the eight agree: `0xCCC0` is Sync and `0xCCC3`
//! is Context in each. The other six mean different things — `0xCCC1` CodecVersions vs
//! FrameBegin, `0xCCC2` Channels vs FrameEnd, `0xCCC4` FrameBegin vs Region, `0xCCC5`
//! FrameEnd vs TileSimple, `0xCCC6` Region vs TileFirst, `0xCCC7` TileSet vs TileUpgrade
//! ([`super`] holds the first of each pair). So **no block constant crosses the module
//! boundary**; this module declares its own eight. What *is* shared is only what the two
//! streams genuinely agree on: [`super::SYNC_MAGIC`], [`super::SYNC_VERSION`],
//! [`super::TILE_DIM`], and the [`super::RfxRect`] type, which is one structure in both.
//!
//! Structure differs from WireToSurface1 in one more way that shapes the API: the tile blocks
//! are **not** stream-level. They live inside a region block's declared `tileDataSize` window,
//! so [`ProgressiveMessage`] has no tile variant and [`ProgressiveRegion::tiles`] is the only
//! place a tile can appear.
//!
//! **What this layer deliberately does not check, and who inherits it.** Recorded here because
//! a parse layer that validates *most* of a field's constraints reads, from downstream, like
//! one that validated all of them:
//!
//! - **Block ordering.** FreeRDP tracks a `WBT_STATE_FLAG` machine — duplicate `SYNC`,
//!   `FRAME_BEGIN` twice, a region outside a frame, `FRAME_BEGIN` after `FRAME_END`. None of it
//!   is here: like the sibling WireToSurface1 parser, a message list may legitimately start
//!   mid-frame, so ordering is decoder state. It belongs to the context lifecycle (#170).
//! - **Quant *values*.** The bands are 4-bit so `<= 15` holds by construction, but the `>= 6`
//!   floor the dequantizer needs is not enforced. The sources genuinely contradict each other:
//!   FreeRDP rejects such a region outright, while `ironrdp-graphics` defines a rounding
//!   right-shift for `q < 6` and decodes it. Left open on purpose — and note the trap for
//!   #171, since agreeing with the oracle here proves nothing, the oracle being the reference
//!   that tolerates it (`docs/map/invariant/oracle-agreement-is-not-independence.md`).
//! - **Tile grid position.** `x_idx`/`y_idx` are unbounded here because the surface dimensions
//!   are not in this stream; they are bounded where the tile is placed (#169).

use super::{RfxRect, SYNC_MAGIC, SYNC_VERSION, TILE_DIM};
use crate::cursor::ReadCursor;
use crate::error::DecodeError;

/// `WBT_SYNC` — RFX_PROGRESSIVE_SYNC block type.
pub const BLOCK_SYNC: u16 = 0xCCC0;
/// `WBT_FRAME_BEGIN` — RFX_PROGRESSIVE_FRAME_BEGIN block type.
pub const BLOCK_FRAME_BEGIN: u16 = 0xCCC1;
/// `WBT_FRAME_END` — RFX_PROGRESSIVE_FRAME_END block type.
pub const BLOCK_FRAME_END: u16 = 0xCCC2;
/// `WBT_CONTEXT` — RFX_PROGRESSIVE_CONTEXT block type.
pub const BLOCK_CONTEXT: u16 = 0xCCC3;
/// `WBT_REGION` — RFX_PROGRESSIVE_REGION block type.
pub const BLOCK_REGION: u16 = 0xCCC4;
/// `WBT_TILE_SIMPLE` — RFX_PROGRESSIVE_TILE_SIMPLE, nested in a region.
pub const BLOCK_TILE_SIMPLE: u16 = 0xCCC5;
/// `WBT_TILE_FIRST` — RFX_PROGRESSIVE_TILE_FIRST, nested in a region.
pub const BLOCK_TILE_FIRST: u16 = 0xCCC6;
/// `WBT_TILE_UPGRADE` — RFX_PROGRESSIVE_TILE_UPGRADE, nested in a region.
pub const BLOCK_TILE_UPGRADE: u16 = 0xCCC7;

/// Every progressive block opens with `blockType(u16) + blockLen(u32)`; `blockLen` counts the
/// header itself.
pub const BLOCK_HEADER_LEN: usize = 6;

/// `RFX_SUBBAND_DIFFING` — [`ProgressiveMessage::Context`] flag: tiles are coded as a
/// difference against the previous frame's coefficients.
pub const CONTEXT_FLAG_SUBBAND_DIFFING: u8 = 0x01;
/// `RFX_DWT_REDUCE_EXTRAPOLATE` — [`ProgressiveRegion::flags`]: the DWT uses the asymmetric
/// (reduce-extrapolate) band sizes rather than the classic symmetric split.
pub const REGION_FLAG_DWT_REDUCE_EXTRAPOLATE: u8 = 0x01;
/// `RFX_TILE_DIFFERENCE` — [`FirstPassTile::flags`]: this tile's coefficients are a difference
/// against the stored ones rather than a replacement.
pub const TILE_FLAG_DIFFERENCE: u8 = 0x01;

/// The `quality` value that is a **sentinel, not an index**: full quality, i.e. no progressive
/// quantization on top of the region's base table. Both references special-case it before
/// indexing `prog_quants`, so it is in range whatever that table's length is.
pub const QUALITY_FULL: u8 = 0xFF;

/// The largest quantization table a region may declare (both references reject 8 or more).
const MAX_QUANT: usize = 7;
/// `RFX_COMPONENT_CODEC_QUANT` — 10 nibbles in 5 bytes.
const QUANT_LEN: usize = 5;
/// `RFX_PROGRESSIVE_CODEC_QUANT` — a quality byte plus three component quants.
const PROG_QUANT_LEN: usize = 1 + 3 * QUANT_LEN;
/// `RFX_RECT` — four `u16`s.
const RECT_LEN: usize = 8;

/// One `RFX_COMPONENT_CODEC_QUANT`: a 4-bit quantization exponent per DWT subband.
///
/// **The nibble order is not [`super::Quant`]'s.** Progressive swaps HL and LH at every level:
/// classic packs `LL3, LH3, HL3, HH3, LH2, HL2, HH2, LH1, HL1, HH1`, progressive packs
/// `LL3, HL3, LH3, HH3, HL2, LH2, HH2, HL1, LH1, HH1`. Reading one with the other's decoder
/// yields plausible values with two bands transposed — silent, so the two types stay distinct
/// rather than sharing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressiveQuant {
    /// Level-3 lowpass.
    pub ll3: u8,
    /// Level-3 vertical highpass.
    pub hl3: u8,
    /// Level-3 horizontal highpass.
    pub lh3: u8,
    /// Level-3 diagonal highpass.
    pub hh3: u8,
    /// Level-2 vertical highpass.
    pub hl2: u8,
    /// Level-2 horizontal highpass.
    pub lh2: u8,
    /// Level-2 diagonal highpass.
    pub hh2: u8,
    /// Level-1 vertical highpass.
    pub hl1: u8,
    /// Level-1 horizontal highpass.
    pub lh1: u8,
    /// Level-1 diagonal highpass.
    pub hh1: u8,
}

impl ProgressiveQuant {
    fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let b0 = cur.read_u8()?;
        let b1 = cur.read_u8()?;
        let b2 = cur.read_u8()?;
        let b3 = cur.read_u8()?;
        let b4 = cur.read_u8()?;
        Ok(Self {
            ll3: b0 & 0x0F,
            hl3: b0 >> 4,
            lh3: b1 & 0x0F,
            hh3: b1 >> 4,
            hl2: b2 & 0x0F,
            lh2: b2 >> 4,
            hh2: b3 & 0x0F,
            hl1: b3 >> 4,
            lh1: b4 & 0x0F,
            hh1: b4 >> 4,
        })
    }
}

/// One `RFX_PROGRESSIVE_CODEC_QUANT`: the per-quality bit-position table an upgrade pass
/// indexes by [`UpgradeTile::quality`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressiveCodecQuant {
    /// The quality level this entry describes.
    pub quality: u8,
    /// Luma bit positions.
    pub y: ProgressiveQuant,
    /// Blue-difference chroma bit positions.
    pub cb: ProgressiveQuant,
    /// Red-difference chroma bit positions.
    pub cr: ProgressiveQuant,
}

impl ProgressiveCodecQuant {
    fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            quality: cur.read_u8()?,
            y: ProgressiveQuant::decode(cur)?,
            cb: ProgressiveQuant::decode(cur)?,
            cr: ProgressiveQuant::decode(cur)?,
        })
    }
}

/// A first-pass tile — `RFX_PROGRESSIVE_TILE_SIMPLE` or `RFX_PROGRESSIVE_TILE_FIRST`. The two
/// share a body except for the `quality` byte, which only TILE_FIRST carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirstPassTile<'a> {
    /// Index into the region's quant table for the luma component.
    pub quant_idx_y: u8,
    /// Index into the region's quant table for the blue-difference chroma component.
    pub quant_idx_cb: u8,
    /// Index into the region's quant table for the red-difference chroma component.
    pub quant_idx_cr: u8,
    /// Tile column in the 64×64 grid (pixel x = `x_idx * 64`).
    pub x_idx: u16,
    /// Tile row in the 64×64 grid (pixel y = `y_idx * 64`).
    pub y_idx: u16,
    /// Tile flags — see [`TILE_FLAG_DIFFERENCE`].
    pub flags: u8,
    /// The quality level, indexing the region's progressive-quant table — except for
    /// [`QUALITY_FULL`], which is a sentinel rather than an index. Validated against
    /// [`ProgressiveRegion::prog_quants`] at parse time.
    ///
    /// `None` on TILE_SIMPLE, which has no such field on the wire — a single-pass tile is
    /// complete at the region's base quantization and no upgrade pass refines it. (FreeRDP
    /// synthesizes [`QUALITY_FULL`] here instead; a value the wire never carried is exactly
    /// what `None` avoids inventing.)
    pub quality: Option<u8>,
    /// RLGR-coded luma coefficients.
    pub y_data: &'a [u8],
    /// RLGR-coded Cb coefficients.
    pub cb_data: &'a [u8],
    /// RLGR-coded Cr coefficients.
    pub cr_data: &'a [u8],
    /// The trailing `tailData` run, sized by `tailLen`.
    pub tail_data: &'a [u8],
}

/// An `RFX_PROGRESSIVE_TILE_UPGRADE` — one refinement pass over a tile a previous PDU
/// established. Each component arrives as an SRL run and a raw-bit run rather than one stream,
/// and there is **no `flags` byte**: an upgrade is a refinement by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeTile<'a> {
    /// Index into the region's quant table for the luma component.
    pub quant_idx_y: u8,
    /// Index into the region's quant table for the blue-difference chroma component.
    pub quant_idx_cb: u8,
    /// Index into the region's quant table for the red-difference chroma component.
    pub quant_idx_cr: u8,
    /// Tile column in the 64×64 grid (pixel x = `x_idx * 64`).
    pub x_idx: u16,
    /// Tile row in the 64×64 grid (pixel y = `y_idx * 64`).
    pub y_idx: u16,
    /// The quality level this pass upgrades to, indexing the region's progressive-quant table
    /// — except for [`QUALITY_FULL`], which is a sentinel rather than an index. Validated
    /// against [`ProgressiveRegion::prog_quants`] at parse time.
    pub quality: u8,
    /// SRL-coded luma refinement.
    pub y_srl: &'a [u8],
    /// Raw-bit luma refinement.
    pub y_raw: &'a [u8],
    /// SRL-coded Cb refinement.
    pub cb_srl: &'a [u8],
    /// Raw-bit Cb refinement.
    pub cb_raw: &'a [u8],
    /// SRL-coded Cr refinement.
    pub cr_srl: &'a [u8],
    /// Raw-bit Cr refinement.
    pub cr_raw: &'a [u8],
}

/// One tile record inside a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressiveTile<'a> {
    /// `WBT_TILE_SIMPLE` — a complete tile at the region's base quantization; no upgrade
    /// pass follows it.
    Simple(FirstPassTile<'a>),
    /// `WBT_TILE_FIRST` — the coarse first pass of a tile that upgrade passes refine.
    First(FirstPassTile<'a>),
    /// `WBT_TILE_UPGRADE` — one refinement pass.
    Upgrade(UpgradeTile<'a>),
}

/// An `RFX_PROGRESSIVE_REGION`: the clip rectangles, the two quantization tables tiles index
/// into, and the tiles themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressiveRegion<'a> {
    /// The clip rectangles, in pixels relative to the surface origin. At least one.
    pub rects: Vec<RfxRect>,
    /// The base quantization table (at most seven entries); every tile's `quantIdx` is
    /// validated against its length. The band *values* are not range-checked — see the module
    /// doc for why that is left to the layer that consumes them.
    pub quants: Vec<ProgressiveQuant>,
    /// The progressive (per-quality bit-position) table tiles index by `quality`; every tile's
    /// `quality` is validated against its length, [`QUALITY_FULL`] excepted.
    pub prog_quants: Vec<ProgressiveCodecQuant>,
    /// Region flags — see [`REGION_FLAG_DWT_REDUCE_EXTRAPOLATE`].
    pub flags: u8,
    /// The tiles carried in the region's `tileDataSize` window.
    pub tiles: Vec<ProgressiveTile<'a>>,
}

/// One parsed stream-level progressive block. Tiles are absent by design — they are nested in
/// [`ProgressiveRegion::tiles`], never stream-level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressiveMessage<'a> {
    /// RFX_PROGRESSIVE_SYNC — stream start marker (magic/version validated).
    Sync,
    /// RFX_PROGRESSIVE_FRAME_BEGIN.
    FrameBegin {
        /// Server frame counter.
        index: u32,
        /// The number of regions the frame claims. A server may over-declare it; the decoder
        /// is expected to tolerate the inconsistency rather than wait for regions that never
        /// arrive, so this is reported, not enforced.
        regions: u16,
    },
    /// RFX_PROGRESSIVE_FRAME_END.
    FrameEnd,
    /// RFX_PROGRESSIVE_CONTEXT — the stream-wide coding parameters.
    Context {
        /// The context id the block declares. Servers are expected to send 0; a non-zero
        /// value is reported rather than rejected (the EGFX `codecContextId` is what actually
        /// keys decoder state, epic #158 slice 4).
        ctx_id: u8,
        /// Context flags — see [`CONTEXT_FLAG_SUBBAND_DIFFING`].
        flags: u8,
    },
    /// RFX_PROGRESSIVE_REGION — the clip rectangles, quant tables and tiles.
    Region(ProgressiveRegion<'a>),
}

fn invalid(field: &'static str, reason: &'static str) -> DecodeError {
    DecodeError::InvalidField { field, reason }
}

/// Walk every progressive block in `data` (one complete WireToSurface2 payload) into typed
/// messages. Malformed framing or field values are a typed error, never a panic.
///
/// Unlike the sibling WireToSurface1 walker, an **unknown block type is an error, not a
/// skip**: both reference decoders reject one, and a skipped block here could have been a
/// region whose tiles later passes depend on — dropping it silently would corrupt the
/// multi-pass coefficient state rather than lose one frame.
pub fn decode_all(data: &[u8]) -> Result<Vec<ProgressiveMessage<'_>>, DecodeError> {
    let mut cur = ReadCursor::new(data, "RFX_PROGRESSIVE block stream");
    let mut messages = Vec::new();
    while cur.remaining() > 0 {
        let (block_type, block_len, body) = read_block(&mut cur, "RFX_PROGRESSIVE_BLOCK")?;
        let mut body = ReadCursor::new(body, "RFX_PROGRESSIVE block body");
        let message = match block_type {
            BLOCK_SYNC => {
                expect_block_len(block_len, 12, "RFX_PROGRESSIVE_SYNC.blockLen")?;
                decode_sync(&mut body)?
            }
            BLOCK_FRAME_BEGIN => {
                expect_block_len(block_len, 12, "RFX_PROGRESSIVE_FRAME_BEGIN.blockLen")?;
                ProgressiveMessage::FrameBegin {
                    index: body.read_u32_le()?,
                    regions: body.read_u16_le()?,
                }
            }
            BLOCK_FRAME_END => {
                expect_block_len(block_len, 6, "RFX_PROGRESSIVE_FRAME_END.blockLen")?;
                ProgressiveMessage::FrameEnd
            }
            BLOCK_CONTEXT => {
                expect_block_len(block_len, 10, "RFX_PROGRESSIVE_CONTEXT.blockLen")?;
                decode_context(&mut body)?
            }
            BLOCK_REGION => ProgressiveMessage::Region(decode_region(&mut body)?),
            BLOCK_TILE_SIMPLE | BLOCK_TILE_FIRST | BLOCK_TILE_UPGRADE => {
                return Err(invalid(
                    "RFX_PROGRESSIVE_BLOCK.blockType",
                    "a tile block outside a region",
                ));
            }
            _ => {
                return Err(invalid(
                    "RFX_PROGRESSIVE_BLOCK.blockType",
                    "unknown progressive block type",
                ));
            }
        };
        messages.push(message);
    }
    Ok(messages)
}

/// Read one `blockType(u16) + blockLen(u32)` header and slice off exactly the body it frames.
/// Returns the type, the *whole* block length (what the fixed-size checks compare against) and
/// the body bytes.
fn read_block<'a>(
    cur: &mut ReadCursor<'a>,
    field: &'static str,
) -> Result<(u16, usize, &'a [u8]), DecodeError> {
    let block_type = cur.read_u16_le()?;
    // `as usize` is lossless here on every target the crate builds for (u32 fits a usize at 32
    // bits and above) and is the sibling WireToSurface1 walker's idiom; the length is bounded
    // by `read_slice` below, which fails rather than over-reading.
    let block_len = cur.read_u32_le()? as usize;
    let body_len = block_len
        .checked_sub(BLOCK_HEADER_LEN)
        .ok_or(invalid(field, "block length shorter than its own header"))?;
    Ok((block_type, block_len, cur.read_slice(body_len)?))
}

/// Both references reject a fixed-size block whose `blockLen` is not the one the format fixes,
/// rather than trusting the body and ignoring the count.
fn expect_block_len(
    actual: usize,
    expected: usize,
    field: &'static str,
) -> Result<(), DecodeError> {
    if actual == expected {
        Ok(())
    } else {
        Err(invalid(field, "not the length this block type fixes"))
    }
}

fn decode_sync(cur: &mut ReadCursor<'_>) -> Result<ProgressiveMessage<'static>, DecodeError> {
    if cur.read_u32_le()? != SYNC_MAGIC {
        return Err(invalid(
            "RFX_PROGRESSIVE_SYNC.magicNumber",
            "expected 0xCACCACCA",
        ));
    }
    if cur.read_u16_le()? != SYNC_VERSION {
        return Err(invalid(
            "RFX_PROGRESSIVE_SYNC.version",
            "expected WF_VERSION_1_0",
        ));
    }
    Ok(ProgressiveMessage::Sync)
}

fn decode_context(cur: &mut ReadCursor<'_>) -> Result<ProgressiveMessage<'static>, DecodeError> {
    let ctx_id = cur.read_u8()?;
    if cur.read_u16_le()? != TILE_DIM {
        return Err(invalid(
            "RFX_PROGRESSIVE_CONTEXT.tileSize",
            "must be 64 (CT_TILE_64x64)",
        ));
    }
    Ok(ProgressiveMessage::Context {
        ctx_id,
        flags: cur.read_u8()?,
    })
}

fn decode_region<'a>(cur: &mut ReadCursor<'a>) -> Result<ProgressiveRegion<'a>, DecodeError> {
    if u16::from(cur.read_u8()?) != TILE_DIM {
        return Err(invalid(
            "RFX_PROGRESSIVE_REGION.tileSize",
            "must be 64 (CT_TILE_64x64)",
        ));
    }
    let num_rects = usize::from(cur.read_u16_le()?);
    let num_quant = usize::from(cur.read_u8()?);
    let num_prog_quant = usize::from(cur.read_u8()?);
    let flags = cur.read_u8()?;
    // `numTiles` is deliberately not bound to a variable: the tile loop below is driven by the
    // declared `tileDataSize` window instead, and a count that disagrees with what the window
    // holds is tolerated rather than rejected.
    //
    // This is **more tolerant than either reference**, not a copy of one. FreeRDP requires both
    // to agree — `progressive_process_tiles` drives by the window and then returns -1044 on a
    // `numTiles` mismatch and -1041 unless the window is consumed exactly (the WLOG_WARN there
    // is the log level, not the outcome). IronRDP drives by the count and discards the window
    // entirely. Tolerance is the permitted direction on a receive path: a server whose count
    // and window disagree has still framed the tiles unambiguously, and the alternative is
    // dropping a frame we can read.
    let _num_tiles = cur.read_u16_le()?;
    let tile_data_size = cur.read_u32_le()? as usize;

    if num_rects == 0 {
        return Err(invalid(
            "RFX_PROGRESSIVE_REGION.numRects",
            "a region must clip to at least one rectangle",
        ));
    }
    if num_quant > MAX_QUANT {
        return Err(invalid(
            "RFX_PROGRESSIVE_REGION.numQuant",
            "more quant entries than the table may hold",
        ));
    }
    // Each count is a u16/u8 times a small constant, so the sum cannot overflow a 32-bit
    // usize; check it against the buffer *before* reserving, so a 6-byte header can never
    // make us allocate for tables that are not there.
    let declared = num_rects * RECT_LEN + num_quant * QUANT_LEN + num_prog_quant * PROG_QUANT_LEN;
    if cur.remaining() < declared {
        return Err(invalid(
            "RFX_PROGRESSIVE_REGION",
            "declared tables longer than the block body",
        ));
    }

    let mut rects = Vec::with_capacity(num_rects);
    for _ in 0..num_rects {
        rects.push(RfxRect {
            x: cur.read_u16_le()?,
            y: cur.read_u16_le()?,
            width: cur.read_u16_le()?,
            height: cur.read_u16_le()?,
        });
    }
    let mut quants = Vec::with_capacity(num_quant);
    for _ in 0..num_quant {
        quants.push(ProgressiveQuant::decode(cur)?);
    }
    let mut prog_quants = Vec::with_capacity(num_prog_quant);
    for _ in 0..num_prog_quant {
        prog_quants.push(ProgressiveCodecQuant::decode(cur)?);
    }

    let tiles = decode_tiles(
        cur.read_slice(tile_data_size)?,
        quants.len(),
        prog_quants.len(),
    )?;
    Ok(ProgressiveRegion {
        rects,
        quants,
        prog_quants,
        flags,
        tiles,
    })
}

/// Walk the region's tile window, validating every table index the tiles carry against the
/// tables the region declared — the two are in hand together exactly here, and nowhere later.
///
/// The window bounds the walk: a block whose length runs past it is an error. Trailing bytes
/// too short to hold a header are left unread, which is **laxer than either reference** (both
/// require the window consumed exactly). The asymmetry with [`decode_all`], which rejects the
/// same 1–5 stray bytes at stream level, is deliberate and is about what the slack can do: at
/// stream level nothing declared how long the stream was, so a partial header means the framing
/// has desynchronized and every later block is suspect; inside a window whose length the server
/// itself declared, slack is padding the walk skips wholesale and no later block can be
/// misaligned by it.
fn decode_tiles(
    window: &[u8],
    quant_count: usize,
    prog_quant_count: usize,
) -> Result<Vec<ProgressiveTile<'_>>, DecodeError> {
    let mut cur = ReadCursor::new(window, "RFX_PROGRESSIVE_REGION tile window");
    let mut tiles = Vec::new();
    while cur.remaining() >= BLOCK_HEADER_LEN {
        let (block_type, _block_len, body) = read_block(&mut cur, "RFX_PROGRESSIVE_TILE")?;
        let mut body = ReadCursor::new(body, "RFX_PROGRESSIVE tile body");
        let tile = match block_type {
            BLOCK_TILE_SIMPLE => ProgressiveTile::Simple(decode_first_pass_tile(&mut body, false)?),
            BLOCK_TILE_FIRST => ProgressiveTile::First(decode_first_pass_tile(&mut body, true)?),
            BLOCK_TILE_UPGRADE => ProgressiveTile::Upgrade(decode_upgrade_tile(&mut body)?),
            _ => {
                return Err(invalid(
                    "RFX_PROGRESSIVE_TILE.blockType",
                    "not a tile block type",
                ));
            }
        };
        let (quant_indices, quality) = match tile {
            ProgressiveTile::Simple(t) | ProgressiveTile::First(t) => {
                ([t.quant_idx_y, t.quant_idx_cb, t.quant_idx_cr], t.quality)
            }
            ProgressiveTile::Upgrade(t) => (
                [t.quant_idx_y, t.quant_idx_cb, t.quant_idx_cr],
                Some(t.quality),
            ),
        };
        for idx in quant_indices {
            if usize::from(idx) >= quant_count {
                return Err(invalid(
                    "RFX_PROGRESSIVE_TILE.quantIdx",
                    "index beyond the region's quant table",
                ));
            }
        }
        // `quality` indexes the region's *other* table, so it needs the same bound — leaving it
        // out would have made this walk validate one wire-supplied table index and not the
        // other. [`QUALITY_FULL`] is a sentinel, not an index, and is in range by definition.
        if let Some(quality) = quality
            && quality != QUALITY_FULL
            && usize::from(quality) >= prog_quant_count
        {
            return Err(invalid(
                "RFX_PROGRESSIVE_TILE.quality",
                "index beyond the region's progressive-quant table",
            ));
        }
        tiles.push(tile);
    }
    Ok(tiles)
}

/// TILE_SIMPLE and TILE_FIRST share a body; only TILE_FIRST carries `quality`, which is why
/// the two references size the fixed part 16 vs 17.
fn decode_first_pass_tile<'a>(
    cur: &mut ReadCursor<'a>,
    has_quality: bool,
) -> Result<FirstPassTile<'a>, DecodeError> {
    let quant_idx_y = cur.read_u8()?;
    let quant_idx_cb = cur.read_u8()?;
    let quant_idx_cr = cur.read_u8()?;
    let x_idx = cur.read_u16_le()?;
    let y_idx = cur.read_u16_le()?;
    let flags = cur.read_u8()?;
    let quality = if has_quality {
        Some(cur.read_u8()?)
    } else {
        None
    };
    let y_len = usize::from(cur.read_u16_le()?);
    let cb_len = usize::from(cur.read_u16_le()?);
    let cr_len = usize::from(cur.read_u16_le()?);
    let tail_len = usize::from(cur.read_u16_le()?);
    Ok(FirstPassTile {
        quant_idx_y,
        quant_idx_cb,
        quant_idx_cr,
        x_idx,
        y_idx,
        flags,
        quality,
        y_data: cur.read_slice(y_len)?,
        cb_data: cur.read_slice(cb_len)?,
        cr_data: cur.read_slice(cr_len)?,
        tail_data: cur.read_slice(tail_len)?,
    })
}

fn decode_upgrade_tile<'a>(cur: &mut ReadCursor<'a>) -> Result<UpgradeTile<'a>, DecodeError> {
    let quant_idx_y = cur.read_u8()?;
    let quant_idx_cb = cur.read_u8()?;
    let quant_idx_cr = cur.read_u8()?;
    let x_idx = cur.read_u16_le()?;
    let y_idx = cur.read_u16_le()?;
    let quality = cur.read_u8()?;
    let y_srl_len = usize::from(cur.read_u16_le()?);
    let y_raw_len = usize::from(cur.read_u16_le()?);
    let cb_srl_len = usize::from(cur.read_u16_le()?);
    let cb_raw_len = usize::from(cur.read_u16_le()?);
    let cr_srl_len = usize::from(cur.read_u16_le()?);
    let cr_raw_len = usize::from(cur.read_u16_le()?);
    Ok(UpgradeTile {
        quant_idx_y,
        quant_idx_cb,
        quant_idx_cr,
        x_idx,
        y_idx,
        quality,
        y_srl: cur.read_slice(y_srl_len)?,
        y_raw: cur.read_slice(y_raw_len)?,
        cb_srl: cur.read_slice(cb_srl_len)?,
        cb_raw: cur.read_slice(cb_raw_len)?,
        cr_srl: cur.read_slice(cr_srl_len)?,
        cr_raw: cur.read_slice(cr_raw_len)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // ADR-0008 / issue #98 — the no-panic robustness property for a server-controlled PDU
        // parser. Every length in this stream is server-supplied and nested three deep (block
        // -> region window -> tile block -> per-component runs), so the whole `blob` is the
        // attacker-controlled input. Malformed bytes must surface as a typed `DecodeError`,
        // never a panic / arithmetic overflow / OOB read. Reaching the end without unwinding
        // IS the assertion; proptest shrinks any failure to a minimal counterexample.
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn decode_all_never_panics_on_arbitrary_input(
            blob in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = decode_all(&blob);
        }
    }

    /// Append one block: `blockType(u16) + blockLen(u32)` then the body.
    fn push_block(out: &mut Vec<u8>, block_type: u16, body: &[u8]) {
        out.extend_from_slice(&block_type.to_le_bytes());
        out.extend_from_slice(&((BLOCK_HEADER_LEN + body.len()) as u32).to_le_bytes());
        out.extend_from_slice(body);
    }

    fn block(block_type: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_block(&mut out, block_type, body);
        out
    }

    fn sync_body() -> Vec<u8> {
        let mut b = SYNC_MAGIC.to_le_bytes().to_vec();
        b.extend_from_slice(&SYNC_VERSION.to_le_bytes());
        b
    }

    fn frame_begin_body(index: u32, regions: u16) -> Vec<u8> {
        let mut b = index.to_le_bytes().to_vec();
        b.extend_from_slice(&regions.to_le_bytes());
        b
    }

    fn context_body(ctx_id: u8, flags: u8) -> Vec<u8> {
        let mut b = vec![ctx_id];
        b.extend_from_slice(&TILE_DIM.to_le_bytes());
        b.push(flags);
        b
    }

    /// The five progressive nibble bytes for a quant whose ten bands ascend from `base`.
    fn quant_bytes(base: u8) -> [u8; QUANT_LEN] {
        let v = |i: u8| (base + i) & 0x0F;
        [
            v(0) | (v(1) << 4),
            v(2) | (v(3) << 4),
            v(4) | (v(5) << 4),
            v(6) | (v(7) << 4),
            v(8) | (v(9) << 4),
        ]
    }

    fn quant_from(base: u8) -> ProgressiveQuant {
        let v = |i: u8| (base + i) & 0x0F;
        ProgressiveQuant {
            ll3: v(0),
            hl3: v(1),
            lh3: v(2),
            hh3: v(3),
            hl2: v(4),
            lh2: v(5),
            hh2: v(6),
            hl1: v(7),
            lh1: v(8),
            hh1: v(9),
        }
    }

    #[expect(clippy::too_many_arguments, reason = "one argument per wire field")]
    fn first_pass_tile_block(
        block_type: u16,
        quant_idx: [u8; 3],
        x_idx: u16,
        y_idx: u16,
        flags: u8,
        quality: Option<u8>,
        y: &[u8],
        cb: &[u8],
        cr: &[u8],
        tail: &[u8],
    ) -> Vec<u8> {
        let mut body = quant_idx.to_vec();
        body.extend_from_slice(&x_idx.to_le_bytes());
        body.extend_from_slice(&y_idx.to_le_bytes());
        body.push(flags);
        if let Some(q) = quality {
            body.push(q);
        }
        for part in [y, cb, cr, tail] {
            body.extend_from_slice(&(part.len() as u16).to_le_bytes());
        }
        for part in [y, cb, cr, tail] {
            body.extend_from_slice(part);
        }
        block(block_type, &body)
    }

    fn upgrade_tile_block(
        quant_idx: [u8; 3],
        x_idx: u16,
        y_idx: u16,
        quality: u8,
        runs: [&[u8]; 6],
    ) -> Vec<u8> {
        let mut body = quant_idx.to_vec();
        body.extend_from_slice(&x_idx.to_le_bytes());
        body.extend_from_slice(&y_idx.to_le_bytes());
        body.push(quality);
        for run in runs {
            body.extend_from_slice(&(run.len() as u16).to_le_bytes());
        }
        for run in runs {
            body.extend_from_slice(run);
        }
        block(BLOCK_TILE_UPGRADE, &body)
    }

    /// Assemble a region body from its parts, deriving `numTiles` and `tileDataSize` from the
    /// tile blocks so a test that changes the tiles cannot leave the header stale.
    fn region_body(
        rects: &[(u16, u16, u16, u16)],
        quants: &[[u8; QUANT_LEN]],
        prog_quants: &[(u8, u8)],
        flags: u8,
        tiles: &[Vec<u8>],
    ) -> Vec<u8> {
        let tile_data: Vec<u8> = tiles.iter().flatten().copied().collect();
        let mut b = vec![TILE_DIM as u8];
        b.extend_from_slice(&(rects.len() as u16).to_le_bytes());
        b.push(quants.len() as u8);
        b.push(prog_quants.len() as u8);
        b.push(flags);
        b.extend_from_slice(&(tiles.len() as u16).to_le_bytes());
        b.extend_from_slice(&(tile_data.len() as u32).to_le_bytes());
        for &(x, y, w, h) in rects {
            for v in [x, y, w, h] {
                b.extend_from_slice(&v.to_le_bytes());
            }
        }
        for q in quants {
            b.extend_from_slice(q);
        }
        for &(quality, base) in prog_quants {
            b.push(quality);
            for component in 0..3u8 {
                b.extend_from_slice(&quant_bytes(base + component));
            }
        }
        b.extend_from_slice(&tile_data);
        b
    }

    #[test]
    fn a_full_frame_parses_every_stream_level_block_in_order() {
        let mut data = Vec::new();
        push_block(&mut data, BLOCK_SYNC, &sync_body());
        push_block(
            &mut data,
            BLOCK_CONTEXT,
            &context_body(0, CONTEXT_FLAG_SUBBAND_DIFFING),
        );
        push_block(&mut data, BLOCK_FRAME_BEGIN, &frame_begin_body(7, 1));
        // Distinct values throughout: a different quant index per component, an asymmetric
        // rect, and x_idx != y_idx — so a parser that transposed any pair would be caught.
        let tile = first_pass_tile_block(
            BLOCK_TILE_SIMPLE,
            [0, 1, 2],
            2,
            3,
            0,
            None,
            &[0xAA; 3],
            &[0xBB; 2],
            &[0xCC; 4],
            &[0xDD; 1],
        );
        push_block(
            &mut data,
            BLOCK_REGION,
            &region_body(
                &[(16, 32, 64, 128)],
                &[quant_bytes(6), quant_bytes(7), quant_bytes(8)],
                &[],
                REGION_FLAG_DWT_REDUCE_EXTRAPOLATE,
                &[tile],
            ),
        );
        push_block(&mut data, BLOCK_FRAME_END, &[]);

        let messages = decode_all(&data).expect("valid stream");
        assert_eq!(messages.len(), 5);
        assert_eq!(messages[0], ProgressiveMessage::Sync);
        assert_eq!(
            messages[1],
            ProgressiveMessage::Context {
                ctx_id: 0,
                flags: CONTEXT_FLAG_SUBBAND_DIFFING
            }
        );
        assert_eq!(
            messages[2],
            ProgressiveMessage::FrameBegin {
                index: 7,
                regions: 1
            }
        );
        let ProgressiveMessage::Region(region) = &messages[3] else {
            panic!("expected a region");
        };
        assert_eq!(
            region.rects,
            vec![RfxRect {
                x: 16,
                y: 32,
                width: 64,
                height: 128
            }]
        );
        assert_eq!(
            region.quants,
            vec![quant_from(6), quant_from(7), quant_from(8)]
        );
        assert!(region.prog_quants.is_empty());
        assert_eq!(region.flags, REGION_FLAG_DWT_REDUCE_EXTRAPOLATE);
        assert_eq!(
            region.tiles,
            vec![ProgressiveTile::Simple(FirstPassTile {
                quant_idx_y: 0,
                quant_idx_cb: 1,
                quant_idx_cr: 2,
                x_idx: 2,
                y_idx: 3,
                flags: 0,
                quality: None,
                y_data: &[0xAA; 3],
                cb_data: &[0xBB; 2],
                cr_data: &[0xCC; 4],
                tail_data: &[0xDD; 1],
            })]
        );
        assert_eq!(messages[4], ProgressiveMessage::FrameEnd);
    }

    #[test]
    fn the_progressive_quant_nibble_order_is_not_the_classic_one() {
        // Run *both* parsers over the same five bytes. The classic one is the sibling module's
        // `Quant`, reached here because a child module sees its parent's private items — which
        // makes this a comparison against production code, not against a test helper.
        let bytes = quant_bytes(0);
        let classic = crate::rfx::Quant::decode(&mut ReadCursor::new(&bytes, "classic quant"))
            .expect("five bytes are a whole quant");

        let mut data = Vec::new();
        push_block(
            &mut data,
            BLOCK_REGION,
            &region_body(&[(0, 0, 64, 64)], &[bytes], &[], 0, &[]),
        );
        let messages = decode_all(&data).expect("region parses");
        let ProgressiveMessage::Region(region) = &messages[0] else {
            panic!("expected a region");
        };
        let progressive = region.quants[0];

        // HL and LH are transposed at all three levels...
        assert_eq!(progressive.hl3, classic.lh3);
        assert_eq!(progressive.lh3, classic.hl3);
        assert_ne!(progressive.hl3, classic.hl3);
        assert_eq!(progressive.hl2, classic.lh2);
        assert_eq!(progressive.lh2, classic.hl2);
        assert_ne!(progressive.hl2, classic.hl2);
        assert_eq!(progressive.hl1, classic.lh1);
        assert_eq!(progressive.lh1, classic.hl1);
        assert_ne!(progressive.hl1, classic.hl1);
        // ...and only there: LL3 and the three diagonal bands read identically, which is why
        // the wrong decoder yields a plausible quant rather than an obviously broken one.
        assert_eq!(progressive.ll3, classic.ll3);
        assert_eq!(progressive.hh3, classic.hh3);
        assert_eq!(progressive.hh2, classic.hh2);
        assert_eq!(progressive.hh1, classic.hh1);
    }

    #[test]
    fn a_region_carries_first_and_upgrade_tiles_with_their_quality_tables() {
        let first = first_pass_tile_block(
            BLOCK_TILE_FIRST,
            [1, 0, 1],
            0,
            0,
            TILE_FLAG_DIFFERENCE,
            Some(0),
            &[0x11],
            &[0x22],
            &[0x33],
            &[],
        );
        // A different grid position from the first-pass tile, and x != y, so a transposition
        // in the upgrade path cannot hide behind (0, 0).
        let upgrade = upgrade_tile_block(
            [1, 1, 0],
            5,
            9,
            1,
            [&[0x41], &[0x42, 0x43], &[0x44], &[], &[0x45], &[0x46]],
        );
        let mut data = Vec::new();
        push_block(
            &mut data,
            BLOCK_REGION,
            &region_body(
                &[(64, 128, 64, 64)],
                &[quant_bytes(6), quant_bytes(7)],
                &[(4, 6), (5, 8)],
                0,
                &[first, upgrade],
            ),
        );

        let messages = decode_all(&data).expect("valid region");
        let ProgressiveMessage::Region(region) = &messages[0] else {
            panic!("expected a region");
        };
        assert_eq!(region.quants.len(), 2);
        assert_eq!(
            region.prog_quants,
            vec![
                ProgressiveCodecQuant {
                    quality: 4,
                    y: quant_from(6),
                    cb: quant_from(7),
                    cr: quant_from(8),
                },
                ProgressiveCodecQuant {
                    quality: 5,
                    y: quant_from(8),
                    cb: quant_from(9),
                    cr: quant_from(10),
                },
            ]
        );
        assert_eq!(
            region.tiles,
            vec![
                ProgressiveTile::First(FirstPassTile {
                    quant_idx_y: 1,
                    quant_idx_cb: 0,
                    quant_idx_cr: 1,
                    x_idx: 0,
                    y_idx: 0,
                    flags: TILE_FLAG_DIFFERENCE,
                    quality: Some(0),
                    y_data: &[0x11],
                    cb_data: &[0x22],
                    cr_data: &[0x33],
                    tail_data: &[],
                }),
                ProgressiveTile::Upgrade(UpgradeTile {
                    quant_idx_y: 1,
                    quant_idx_cb: 1,
                    quant_idx_cr: 0,
                    x_idx: 5,
                    y_idx: 9,
                    quality: 1,
                    y_srl: &[0x41],
                    y_raw: &[0x42, 0x43],
                    cb_srl: &[0x44],
                    cb_raw: &[],
                    cr_srl: &[0x45],
                    cr_raw: &[0x46],
                }),
            ]
        );
    }

    #[test]
    fn a_tile_block_at_stream_level_is_rejected() {
        // The WireToSurface1 sibling would have skipped an unrecognised block by its length.
        // Here a stream-level tile is a framing error: tiles exist only inside a region.
        let data = first_pass_tile_block(
            BLOCK_TILE_SIMPLE,
            [0, 0, 0],
            0,
            0,
            0,
            None,
            &[],
            &[],
            &[],
            &[],
        );
        assert!(decode_all(&data).is_err());
    }

    #[test]
    fn an_unknown_block_type_is_an_error_not_a_skip() {
        let mut data = block(0xCCC8, &[0xDE, 0xAD]);
        data.extend_from_slice(&block(BLOCK_SYNC, &sync_body()));
        assert!(decode_all(&data).is_err());
    }

    #[test]
    fn fixed_size_blocks_reject_a_block_len_that_is_not_theirs() {
        // Sync is exactly 12 bytes; a longer one is a server disagreeing with the format.
        let mut body = sync_body();
        body.push(0x00);
        assert!(decode_all(&block(BLOCK_SYNC, &body)).is_err());
        // FrameEnd is exactly 6 — header only.
        assert!(decode_all(&block(BLOCK_FRAME_END, &[0x00])).is_err());
        // Context is exactly 10.
        let mut body = context_body(0, 0);
        body.push(0x00);
        assert!(decode_all(&block(BLOCK_CONTEXT, &body)).is_err());
        // FrameBegin is exactly 12.
        assert!(decode_all(&block(BLOCK_FRAME_BEGIN, &[0x00; 5])).is_err());
    }

    #[test]
    fn malformed_streams_yield_typed_errors_not_panics() {
        // Truncated header.
        assert!(decode_all(&[0xC0]).is_err());
        // blockLen shorter than the header it counts.
        let mut data = BLOCK_SYNC.to_le_bytes().to_vec();
        data.extend_from_slice(&5u32.to_le_bytes());
        assert!(decode_all(&data).is_err());
        // blockLen longer than the buffer.
        let mut data = BLOCK_SYNC.to_le_bytes().to_vec();
        data.extend_from_slice(&100u32.to_le_bytes());
        assert!(decode_all(&data).is_err());
        // Bad sync magic, right length.
        let mut body = 0xDEAD_BEEFu32.to_le_bytes().to_vec();
        body.extend_from_slice(&SYNC_VERSION.to_le_bytes());
        assert!(decode_all(&block(BLOCK_SYNC, &body)).is_err());
        // Unsupported sync version.
        let mut body = SYNC_MAGIC.to_le_bytes().to_vec();
        body.extend_from_slice(&0x0200u16.to_le_bytes());
        assert!(decode_all(&block(BLOCK_SYNC, &body)).is_err());
        // Context declaring a tile size other than 64.
        let mut body = vec![0u8];
        body.extend_from_slice(&32u16.to_le_bytes());
        body.push(0);
        assert!(decode_all(&block(BLOCK_CONTEXT, &body)).is_err());
    }

    #[test]
    fn region_headers_are_validated_against_both_references() {
        // numRects == 0 — a region that clips to nothing.
        let mut body = region_body(&[(0, 0, 64, 64)], &[quant_bytes(6)], &[], 0, &[]);
        body[1] = 0;
        body[2] = 0;
        assert!(decode_all(&block(BLOCK_REGION, &body)).is_err());
        // tileSize != 64.
        let mut body = region_body(&[(0, 0, 64, 64)], &[quant_bytes(6)], &[], 0, &[]);
        body[0] = 32;
        assert!(decode_all(&block(BLOCK_REGION, &body)).is_err());
        // numQuant > 7 — more quant entries than the table may hold.
        let quants: Vec<[u8; QUANT_LEN]> = (0..8).map(|i| quant_bytes(6 + i as u8)).collect();
        let body = region_body(&[(0, 0, 64, 64)], &quants, &[], 0, &[]);
        assert!(decode_all(&block(BLOCK_REGION, &body)).is_err());
        // A declared table longer than the bytes that follow it.
        let mut body = region_body(&[(0, 0, 64, 64)], &[quant_bytes(6)], &[], 0, &[]);
        body[4] = 4; // numProgQuant, with no progressive quants actually present
        assert!(decode_all(&block(BLOCK_REGION, &body)).is_err());
    }

    #[test]
    fn a_tile_quant_index_beyond_the_region_table_is_rejected() {
        let tile = first_pass_tile_block(
            BLOCK_TILE_SIMPLE,
            [3, 0, 0],
            0,
            0,
            0,
            None,
            &[0xAA],
            &[0xBB],
            &[0xCC],
            &[],
        );
        let body = region_body(&[(0, 0, 64, 64)], &[quant_bytes(6)], &[], 0, &[tile]);
        assert!(decode_all(&block(BLOCK_REGION, &body)).is_err());
    }

    #[test]
    fn a_tile_run_longer_than_its_block_is_rejected() {
        let mut tile = first_pass_tile_block(
            BLOCK_TILE_SIMPLE,
            [0, 0, 0],
            0,
            0,
            0,
            None,
            &[0xAA],
            &[0xBB],
            &[0xCC],
            &[],
        );
        // Tile body offset 8 is yLen's low byte (3 quant idx + 2 + 2 + 1 flags); claim 200
        // luma bytes that are not in the block.
        tile[BLOCK_HEADER_LEN + 8] = 200;
        let body = region_body(&[(0, 0, 64, 64)], &[quant_bytes(6)], &[], 0, &[tile]);
        assert!(decode_all(&block(BLOCK_REGION, &body)).is_err());
    }

    #[test]
    fn tiles_are_bounded_by_tile_data_size_not_by_num_tiles() {
        // Parse what the window holds, and do not police the count against it. This is laxer
        // than both references — FreeRDP's `progressive_process_tiles` drives by the window but
        // then rejects a numTiles mismatch outright (-1044), and IronRDP drives by the count
        // and ignores the window. Tolerance is the permitted direction on a receive path.
        let tile = first_pass_tile_block(
            BLOCK_TILE_SIMPLE,
            [0, 0, 0],
            0,
            0,
            0,
            None,
            &[0xAA],
            &[0xBB],
            &[0xCC],
            &[],
        );
        let mut body = region_body(
            &[(0, 0, 64, 64)],
            &[quant_bytes(6)],
            &[],
            0,
            &[tile.clone(), tile],
        );
        // Over-declare numTiles: the window still holds exactly two tiles.
        body[6] = 9;
        body[7] = 0;
        let data = block(BLOCK_REGION, &body);
        let messages = decode_all(&data).expect("over-declared numTiles");
        let ProgressiveMessage::Region(region) = &messages[0] else {
            panic!("expected a region");
        };
        assert_eq!(region.tiles.len(), 2);
    }

    #[test]
    fn bytes_past_the_tile_window_are_not_read_as_tiles() {
        let tile = first_pass_tile_block(
            BLOCK_TILE_SIMPLE,
            [0, 0, 0],
            0,
            0,
            0,
            None,
            &[0xAA],
            &[0xBB],
            &[0xCC],
            &[],
        );
        let mut body = region_body(
            &[(0, 0, 64, 64)],
            &[quant_bytes(6)],
            &[],
            0,
            &[tile.clone(), tile.clone()],
        );
        // Shrink tileDataSize to one tile: the second must stay unparsed, not overrun.
        let one = tile.len() as u32;
        body[8..12].copy_from_slice(&one.to_le_bytes());
        let data = block(BLOCK_REGION, &body);
        let messages = decode_all(&data).expect("short tile window");
        let ProgressiveMessage::Region(region) = &messages[0] else {
            panic!("expected a region");
        };
        assert_eq!(region.tiles.len(), 1);
    }

    #[test]
    fn a_tile_quality_beyond_the_progressive_quant_table_is_rejected() {
        // `quality` is the region's *other* wire-supplied table index; leaving it unbounded
        // would have made this walk check one of the two. Both references bound it.
        let upgrade = upgrade_tile_block([0, 0, 0], 0, 0, 2, [&[0x41], &[], &[], &[], &[], &[]]);
        let body = region_body(
            &[(0, 0, 64, 64)],
            &[quant_bytes(6)],
            &[(0, 6), (1, 7)], // two entries, so quality 2 is one past the end
            0,
            &[upgrade],
        );
        assert!(decode_all(&block(BLOCK_REGION, &body)).is_err());

        // The same shape with a region that declared no progressive quants at all.
        let first = first_pass_tile_block(
            BLOCK_TILE_FIRST,
            [0, 0, 0],
            0,
            0,
            0,
            Some(0),
            &[0xAA],
            &[],
            &[],
            &[],
        );
        let body = region_body(&[(0, 0, 64, 64)], &[quant_bytes(6)], &[], 0, &[first]);
        assert!(decode_all(&block(BLOCK_REGION, &body)).is_err());
    }

    #[test]
    fn quality_full_is_a_sentinel_and_needs_no_table_entry() {
        // 0xFF means "no progressive quantization", not "entry 255" — a region with an empty
        // progressive table must still accept it, or every full-quality tile would be rejected.
        let upgrade = upgrade_tile_block(
            [0, 0, 0],
            1,
            2,
            QUALITY_FULL,
            [&[0x41], &[], &[], &[], &[], &[]],
        );
        let body = region_body(&[(0, 0, 64, 64)], &[quant_bytes(6)], &[], 0, &[upgrade]);
        let data = block(BLOCK_REGION, &body);
        let messages = decode_all(&data).expect("QUALITY_FULL needs no table entry");
        let ProgressiveMessage::Region(region) = &messages[0] else {
            panic!("expected a region");
        };
        let ProgressiveTile::Upgrade(tile) = region.tiles[0] else {
            panic!("expected an upgrade tile");
        };
        assert_eq!(tile.quality, QUALITY_FULL);
        assert!(region.prog_quants.is_empty());
    }

    #[test]
    fn stray_bytes_at_stream_level_are_rejected() {
        // The counterpart of `bytes_past_the_tile_window_are_not_read_as_tiles`, and the
        // opposite outcome on purpose: nothing declared how long the stream is, so a partial
        // header means the framing has desynchronized rather than that the server padded.
        let mut data = block(BLOCK_SYNC, &sync_body());
        data.extend_from_slice(&[0x00, 0x00, 0x00]);
        assert!(decode_all(&data).is_err());
    }
}
