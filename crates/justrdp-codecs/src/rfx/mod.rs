//! Self-owned WireToSurface1 RemoteFX decoder (MS-RDPRFX, `RDPGFX_CODECID_CAVIDEO`) —
//! issue #58, ADR-0003 phase-2. The first self-owned EGFX tile codec: it skipped the
//! bootstrap phase entirely (the bootstrap crate never had an assembled RemoteFX decoder),
//! so there is no `egfx-bootstrap` gate to drop — `ironrdp-graphics` appears only as the
//! dev-dependency oracle, verified per ADR-0007 (stage-boundary + composed-reference
//! differentials; the real VM never emits CAVIDEO, so synthetic streams are the corpus).
//!
//! The pipeline per tile component is the spec's inverse chain: RLGR entropy decode
//! ([`rlgr`]) → LL3 delta reconstruction → dequantization ([`quant`]) → three-level inverse
//! DWT ([`dwt`]) → ICT color transform (`color::rfx_ycbcr_to_rgba`). The pure-math stages
//! are deliberately separate, reusable functions: a future RemoteFX **Progressive** rewrite
//! consumes the same transforms (issue #58's "natural companion" note), it must not
//! re-implement them. Scope: image mode only — the legacy inter-frame video mode is a typed
//! error, and 4:4:4 fixed 64×64 tiles are the only shape WTS1 carries.

pub mod dwt;
pub mod quant;
pub mod rlgr;

use justrdp_pdu::rfx::{self, EntropyAlgorithm, Quant, RfxMessage, RfxRect, Tile};

use crate::color;
use quant::COMPONENT_LEN;

/// Why a RemoteFX payload failed to decode. Malformed input is always a typed error, never
/// a panic — the EGFX dispatcher warn-and-skips on it (the sibling WTS1 codecs' contract).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RfxError {
    /// The TS_RFX block stream itself is malformed.
    Parse(justrdp_pdu::DecodeError),
    /// A tile component's RLGR stream is malformed.
    Rlgr(rlgr::RlgrError),
    /// The stream's context declares video mode (inter-frame diffing) — outside the image
    /// path WTS1 uses and outside issue #58's scope.
    VideoMode,
}

impl core::fmt::Display for RfxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RfxError::Parse(e) => write!(f, "TS_RFX parse: {e}"),
            RfxError::Rlgr(e) => write!(f, "RLGR decode: {e}"),
            RfxError::VideoMode => write!(f, "RemoteFX video mode is not supported"),
        }
    }
}

impl core::error::Error for RfxError {}

impl From<justrdp_pdu::DecodeError> for RfxError {
    fn from(e: justrdp_pdu::DecodeError) -> Self {
        RfxError::Parse(e)
    }
}

impl From<rlgr::RlgrError> for RfxError {
    fn from(e: rlgr::RlgrError) -> Self {
        RfxError::Rlgr(e)
    }
}

/// The stateful RemoteFX WTS1 decoder. Header messages (Context) arrive only in the first
/// payload of a stream, so the video-mode verdict persists across calls; everything a
/// tileset needs to decode (entropy variant, quant table) travels in the tileset itself.
#[derive(Debug, Default)]
pub struct RemoteFx {
    /// True once a TS_RFX_CONTEXT declared video mode — every later frame is rejected too,
    /// because without inter-frame state the output would silently corrupt.
    video_mode: bool,
}

impl RemoteFx {
    /// A decoder with no stream state yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode one WireToSurface1 CAVIDEO payload into top-down RGBA8888 of the destination
    /// rectangle's `width × height`, or `Ok(None)` for a payload carrying headers only (no
    /// tileset). Tiles land at `(x_idx·64, y_idx·64)` relative to the rectangle's origin,
    /// masked to the frame's TS_RFX_REGION; uncovered pixels are opaque black.
    pub fn decode_to_rgba(
        &mut self,
        data: &[u8],
        width: u16,
        height: u16,
    ) -> Result<Option<Vec<u8>>, RfxError> {
        let messages = rfx::decode_all(data)?;
        let (w, h) = (usize::from(width), usize::from(height));

        let mut out: Option<Vec<u8>> = None;
        // The clip region in force for the current frame: `None` until a TS_RFX_REGION
        // arrives (clip to the full rectangle), then that region's rects (an empty list
        // legitimately paints nothing).
        let mut region: Option<Vec<RfxRect>> = None;
        // One scratch pair reused across every tile and component.
        let mut component = vec![0i16; COMPONENT_LEN];
        let mut scratch = vec![0i16; COMPONENT_LEN];
        let mut tile_rgba = vec![0u8; COMPONENT_LEN * 4];
        let mut planes = TilePlanes::default();

        for message in &messages {
            match message {
                RfxMessage::Context { image_mode, .. } => {
                    self.video_mode = !image_mode;
                    if self.video_mode {
                        return Err(RfxError::VideoMode);
                    }
                }
                RfxMessage::FrameBegin { .. } => region = None,
                RfxMessage::Region(rects) => region = Some(rects.clone()),
                RfxMessage::TileSet(tileset) => {
                    if self.video_mode {
                        return Err(RfxError::VideoMode);
                    }
                    let out = out.get_or_insert_with(|| opaque_black(w, h));
                    for tile in &tileset.tiles {
                        decode_tile(
                            tile,
                            tileset.entropy,
                            &tileset.quants,
                            &mut planes,
                            &mut component,
                            &mut scratch,
                            &mut tile_rgba,
                        )?;
                        blit_tile(out, w, h, tile, &tile_rgba, region.as_deref());
                    }
                }
                RfxMessage::Sync
                | RfxMessage::CodecVersions
                | RfxMessage::Channels(_)
                | RfxMessage::FrameEnd => {}
            }
        }
        Ok(out)
    }
}

/// The three reconstructed component planes of one tile.
struct TilePlanes {
    y: Vec<i16>,
    cb: Vec<i16>,
    cr: Vec<i16>,
}

impl Default for TilePlanes {
    fn default() -> Self {
        Self {
            y: vec![0; COMPONENT_LEN],
            cb: vec![0; COMPONENT_LEN],
            cr: vec![0; COMPONENT_LEN],
        }
    }
}

fn opaque_black(w: usize, h: usize) -> Vec<u8> {
    let mut out = vec![0u8; w * h * 4];
    for px in out.chunks_exact_mut(4) {
        px[3] = 255;
    }
    out
}

/// Run one tile through the full inverse chain into `tile_rgba` (64×64×4).
fn decode_tile(
    tile: &Tile<'_>,
    entropy: EntropyAlgorithm,
    quants: &[Quant],
    planes: &mut TilePlanes,
    component: &mut [i16],
    scratch: &mut [i16],
    tile_rgba: &mut [u8],
) -> Result<(), RfxError> {
    let parts: [(&[u8], u8, &mut Vec<i16>); 3] = [
        (tile.y_data, tile.quant_idx_y, &mut planes.y),
        (tile.cb_data, tile.quant_idx_cb, &mut planes.cb),
        (tile.cr_data, tile.quant_idx_cr, &mut planes.cr),
    ];
    for (data, quant_idx, plane) in parts {
        rlgr::decode(entropy, data, component)?;
        quant::ll3_delta_decode(&mut component[quant::LL3_OFFSET..]);
        // The parser validated every index against the table.
        quant::dequantize(component, &quants[usize::from(quant_idx)]);
        dwt::decode(component, scratch);
        plane.copy_from_slice(component);
    }
    color::rfx_ycbcr_to_rgba(&planes.y, &planes.cb, &planes.cr, tile_rgba);
    Ok(())
}

/// Copy one decoded tile into the output rectangle, clipped to the frame region (or the
/// whole rectangle when no region message arrived) and to the rectangle bounds.
fn blit_tile(
    out: &mut [u8],
    w: usize,
    h: usize,
    tile: &Tile<'_>,
    tile_rgba: &[u8],
    region: Option<&[RfxRect]>,
) {
    let tile_dim = usize::from(rfx::TILE_DIM);
    let tx = usize::from(tile.x_idx) * tile_dim;
    let ty = usize::from(tile.y_idx) * tile_dim;
    let full = [RfxRect {
        x: 0,
        y: 0,
        width: u16::MAX,
        height: u16::MAX,
    }];
    for clip in region.unwrap_or(&full) {
        // Intersect tile ∩ clip ∩ output, all in output coordinates.
        let left = tx.max(usize::from(clip.x)).min(w);
        let top = ty.max(usize::from(clip.y)).min(h);
        let right = (tx + tile_dim)
            .min(usize::from(clip.x).saturating_add(usize::from(clip.width)))
            .min(w);
        let bottom = (ty + tile_dim)
            .min(usize::from(clip.y).saturating_add(usize::from(clip.height)))
            .min(h);
        for row in top..bottom {
            if right <= left {
                break;
            }
            let src = ((row - ty) * tile_dim + (left - tx)) * 4;
            let dst = (row * w + left) * 4;
            let len = (right - left) * 4;
            out[dst..dst + len].copy_from_slice(&tile_rgba[src..src + len]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiles-only frame (no context — the tileset carries everything a frame
    /// needs): one region of `rects` plus `tiles`, each tile's three components `comp`.
    fn stream(rects: &[(u16, u16, u16, u16)], tiles: &[(u16, u16, Vec<u8>)]) -> Vec<u8> {
        fn push_block(out: &mut Vec<u8>, ty: u16, channel: Option<u8>, body: &[u8]) {
            let len = 6 + channel.map_or(0, |_| 2) + body.len();
            out.extend_from_slice(&ty.to_le_bytes());
            out.extend_from_slice(&(len as u32).to_le_bytes());
            if let Some(ch) = channel {
                out.push(1);
                out.push(ch);
            }
            out.extend_from_slice(body);
        }
        let mut data = Vec::new();
        // Region.
        let mut region = vec![0x01u8];
        region.extend_from_slice(&(rects.len() as u16).to_le_bytes());
        for (x, y, w, h) in rects {
            for v in [x, y, w, h] {
                region.extend_from_slice(&v.to_le_bytes());
            }
        }
        region.extend_from_slice(&0xCAC1u16.to_le_bytes());
        region.extend_from_slice(&1u16.to_le_bytes());
        push_block(&mut data, rfx::BLOCK_REGION, Some(0), &region);
        // TileSet with one identity-ish quant (all exponents 1 → no shift).
        let ts_props: u16 = 0x01 | (1 << 4) | (1 << 6) | (0x01 << 10) | (1 << 14);
        let mut ts = Vec::new();
        ts.extend_from_slice(&0xCAC2u16.to_le_bytes());
        ts.extend_from_slice(&0u16.to_le_bytes());
        ts.extend_from_slice(&ts_props.to_le_bytes());
        ts.push(1);
        ts.push(64);
        ts.extend_from_slice(&(tiles.len() as u16).to_le_bytes());
        let tile_blocks: Vec<Vec<u8>> = tiles
            .iter()
            .map(|(x_idx, y_idx, comp)| {
                let mut t = Vec::new();
                t.extend_from_slice(&rfx::BLOCK_TILE.to_le_bytes());
                t.extend_from_slice(&((6 + 13 + comp.len() * 3) as u32).to_le_bytes());
                t.extend_from_slice(&[0, 0, 0]);
                t.extend_from_slice(&x_idx.to_le_bytes());
                t.extend_from_slice(&y_idx.to_le_bytes());
                for _ in 0..3 {
                    t.extend_from_slice(&(comp.len() as u16).to_le_bytes());
                }
                for _ in 0..3 {
                    t.extend_from_slice(comp);
                }
                t
            })
            .collect();
        let data_size: usize = tile_blocks.iter().map(Vec::len).sum();
        ts.extend_from_slice(&(data_size as u32).to_le_bytes());
        ts.extend_from_slice(&[0x11, 0x11, 0x11, 0x11, 0x11]); // all-1 exponents
        for t in &tile_blocks {
            ts.extend_from_slice(t);
        }
        push_block(&mut data, rfx::BLOCK_TILESET, Some(0), &ts);
        data
    }

    #[test]
    fn header_only_payload_yields_no_frame() {
        // Context alone — no tileset, so nothing to paint.
        let properties: u16 = 0x02 | (1 << 3) | (1 << 5) | (0x01 << 9) | (1 << 13);
        let mut ctx = vec![0u8];
        ctx.extend_from_slice(&64u16.to_le_bytes());
        ctx.extend_from_slice(&properties.to_le_bytes());
        let mut data = rfx::BLOCK_CONTEXT.to_le_bytes().to_vec();
        data.extend_from_slice(&((6 + 2 + ctx.len()) as u32).to_le_bytes());
        data.push(1);
        data.push(0xFF);
        data.extend_from_slice(&ctx);
        let mut decoder = RemoteFx::new();
        assert_eq!(decoder.decode_to_rgba(&data, 64, 64).unwrap(), None);
    }

    #[test]
    fn video_mode_context_is_a_typed_error_and_persists() {
        let properties: u16 = (1 << 3) | (1 << 5) | (0x01 << 9) | (1 << 13); // no CODEC_MODE
        let mut ctx = vec![0u8];
        ctx.extend_from_slice(&64u16.to_le_bytes());
        ctx.extend_from_slice(&properties.to_le_bytes());
        let mut data = rfx::BLOCK_CONTEXT.to_le_bytes().to_vec();
        data.extend_from_slice(&((6 + 2 + ctx.len()) as u32).to_le_bytes());
        data.push(1);
        data.push(0xFF);
        data.extend_from_slice(&ctx);
        let mut decoder = RemoteFx::new();
        assert_eq!(
            decoder.decode_to_rgba(&data, 64, 64),
            Err(RfxError::VideoMode)
        );
        // The verdict persists: a later tiles-only payload is still rejected.
        let frame = stream(&[(0, 0, 64, 64)], &[(0, 0, vec![0x00; 8])]);
        assert_eq!(
            decoder.decode_to_rgba(&frame, 64, 64),
            Err(RfxError::VideoMode)
        );
    }

    #[test]
    fn an_all_zero_tile_paints_the_ict_black_inside_the_region_only() {
        // All-zero coefficients → Y = Cb = Cr = 0 → the ICT's black-ish constant; outside
        // the region the buffer keeps its opaque-black initialization. Both are computed
        // through the real pipeline, so assert the *region masking*, not exact colors:
        // a region narrower than the tile must leave the uncovered column untouched.
        let frame = stream(&[(0, 0, 32, 64)], &[(0, 0, vec![0x00; 8])]);
        let mut decoder = RemoteFx::new();
        let rgba = decoder
            .decode_to_rgba(&frame, 64, 64)
            .expect("valid stream")
            .expect("a tileset paints");
        assert_eq!(rgba.len(), 64 * 64 * 4);
        // Inside the region: the decoded value for zero spectrum, alpha 255.
        let inside = &rgba[..4];
        assert_eq!(inside[3], 255);
        // Outside the region (column 32+): exactly the opaque-black initialization.
        let outside = &rgba[(32 * 4)..(32 * 4) + 4];
        assert_eq!(outside, &[0, 0, 0, 255]);
        // And the decoded zero-spectrum pixel differs from raw black (Y=0 maps to 128-ish
        // luma via the +4096 level shift), proving the pipeline actually ran.
        assert_ne!(inside, &[0u8, 0, 0, 255][..]);
    }

    #[test]
    fn tiles_outside_the_rectangle_clip_instead_of_panicking() {
        // A tile at grid (1, 1) against a 70×70 rectangle: only its 6×6 corner lands.
        let frame = stream(&[(0, 0, 70, 70)], &[(1, 1, vec![0x00; 8])]);
        let mut decoder = RemoteFx::new();
        let rgba = decoder
            .decode_to_rgba(&frame, 70, 70)
            .expect("valid stream")
            .expect("a tileset paints");
        assert_eq!(rgba.len(), 70 * 70 * 4);
    }
}
