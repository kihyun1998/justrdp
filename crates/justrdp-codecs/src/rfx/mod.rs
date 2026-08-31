//! Self-owned WireToSurface1 RemoteFX decoder (MS-RDPRFX, `RDPGFX_CODECID_CAVIDEO`) —
//! issue #58, ADR-0003 phase-2. The first self-owned EGFX tile codec: it skipped the
//! bootstrap phase entirely (the bootstrap crate never had an assembled RemoteFX decoder),
//! so it never had a feature gate to drop — and since #189 nothing here does, because
//! `egfx-bootstrap` is gone with its last holder. `ironrdp-graphics` appears only as the
//! dev-dependency oracle, verified per ADR-0007 (stage-boundary + composed-reference
//! differentials; the real VM never emits CAVIDEO, so synthetic streams are the corpus).
//!
//! The pipeline per tile component is the spec's inverse chain: RLGR entropy decode
//! ([`rlgr`]) → LL3 delta reconstruction → dequantization ([`quant`]) → three-level inverse
//! DWT ([`dwt`]) → ICT color transform (`color::rfx_ycbcr_to_rgba`). The pure-math stages
//! are deliberately separate, reusable functions: the RemoteFX **Progressive** decoder
//! ([`progressive`], epic #158) consumes the same transforms (issue #58's "natural companion"
//! note) rather than re-implementing them — with one measured exception, the reduce-extrapolate
//! inverse DWT ([`dwt_extrapolate`], #169), which is a second transform and not a variant of
//! [`dwt`]. Scope: image mode only — the legacy inter-frame video mode is a typed
//! error, and 4:4:4 fixed 64×64 tiles are the only shape WTS1 carries.

pub mod dwt;
pub mod dwt_extrapolate;
pub mod progressive;
pub mod quant;
pub mod rlgr;
pub mod srl;

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
    /// A band's dequantization shift is 16 or wider, which `i16 <<` has no meaning for.
    ///
    /// Unreachable from the wire — `Quant::decode` masks every exponent to `0..=15`, so the
    /// widest shift a server can ask for is 14. The variant exists because that guarantee lives
    /// in `justrdp-pdu`'s parser and not in `Quant`, whose fields are plain `pub u8`
    /// ([ADR-0012](../../../../docs/adr/0012-consumption-site-totality.md) §1). Named to match
    /// `super::progressive::ProgressiveError::ShiftOutOfRange`, which is the same condition at
    /// the same threshold in the sibling stage — where it *is* reachable, because a Progressive
    /// shift is `quant + prog_quant - 1` and runs to 29.
    ShiftOutOfRange(u8),
    /// A band's quantization exponent is 0, so the spec's `shift = exponent - 1` names no
    /// shift at all.
    ///
    /// **Reachable from the wire**, unlike [`RfxError::ShiftOutOfRange`]: `Quant::decode` masks
    /// each field to a nibble and a `0x00` byte is two zero nibbles, so a server can send this.
    /// It is refused anyway, and the distinction that makes that tolerable on a receive path is
    /// the one [ADR-0009](../../../../docs/adr/0009-tolerant-negotiation-posture.md) §3(a)
    /// already draws: tolerance is about *which features may appear*, never about trusting
    /// their contents — and `-1` is not a shift we dislike, it is the absence of one. No
    /// conforming encoder emits it (`[MS-RDPRFX]` constrains the encoder to 6..=15), so there
    /// is no server intent to be tolerant *of*.
    ///
    /// Named to match `super::progressive::ProgressiveError::ZeroBitPosition`, which is the same
    /// condition in the sibling stage. That the two agree is the requirement, not a coincidence
    /// ([ADR-0012](../../../../docs/adr/0012-consumption-site-totality.md) §3, resolving #233).
    ZeroQuantExponent,
    /// The destination rectangle's RGBA byte count cannot be materialized on this target.
    ///
    /// Two ceilings, one quantity. It **overflows `usize`** where `usize` is 32 bits (`i686`,
    /// and `wasm32`, a stated reach goal — ADR-0002 amendment / #100): `[MS-RDPEGFX]` 2.2.1.2
    /// bounds a `RDPGFX_RECT16`'s fields at `u16` and states no maximum, and 2.2.2.1 makes the
    /// rectangle the bitmap's own dimensions, so a server picks both factors and
    /// 65535 x 65535 x 4 = 17_179_344_900 exceeds `u32::MAX`. Or it **exceeds `isize::MAX`**,
    /// the ceiling `Vec` itself enforces — above which it panics with *capacity overflow*
    /// rather than allocating — which on 32-bit is a 2 GiB band the first ceiling does not
    /// cover: `40000 x 20000 x 4` is 3_200_000_000, passes `checked_mul`, and panicked.
    /// Measured, not reasoned about.
    ///
    /// Named to match the same condition in the five sibling codecs that carry it — `color`,
    /// `planar`, `pointer`, `rle`, `nscodec` — one quantity, one answer across a family
    /// ([ADR-0012](../../../../docs/adr/0012-consumption-site-totality.md) §3). **`clearcodec`
    /// is deliberately not in that list**: `clearcodec.rs:98-104` records why it has no variant
    /// of its own and maps the `nscodec` one to `InvalidField` instead. Returned instead of a
    /// debug panic / release wrap (#263, sibling of #151 / #155).
    DimensionsOverflow {
        /// The requested width.
        width: u16,
        /// The requested height.
        height: u16,
    },
}

impl core::fmt::Display for RfxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RfxError::Parse(e) => write!(f, "TS_RFX parse: {e}"),
            RfxError::Rlgr(e) => write!(f, "RLGR decode: {e}"),
            RfxError::VideoMode => write!(f, "RemoteFX video mode is not supported"),
            RfxError::ShiftOutOfRange(n) => {
                write!(
                    f,
                    "a band's dequantization shift is {n}, which must be under 16"
                )
            }
            RfxError::ZeroQuantExponent => {
                write!(
                    f,
                    "a band's quantization exponent is 0, which names no shift"
                )
            }
            RfxError::DimensionsOverflow { width, height } => {
                write!(f, "{width}x{height} pixels overflow usize on this target")
            }
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
        let (w, h) = (usize::from(width), usize::from(height));
        // The output buffer is `w * h * 4` bytes and both factors are `u16`s a server chose:
        // `[MS-RDPEGFX]` 2.2.1.2 bounds a `RDPGFX_RECT16`'s fields at `u16` and nothing else, and
        // 2.2.2.1 makes the rectangle the bitmap's own dimensions. 65535 x 65535 x 4 is
        // 17_179_344_900, which wraps a 32-bit `usize`
        // ([the invariant](../../../../docs/map/invariant/decoder-dimension-overflow-32bit.md)).
        // Refused once, here, before a single block is walked — a rectangle whose pixels cannot
        // be addressed is not decodable at all, so there is nothing to be tolerant *of*.
        //
        // What this does **not** do is bound the *magnitude* below `isize::MAX`. On 64-bit the
        // same product fits and 93 bytes of tileset buy a 16 GiB allocation (measured, #263);
        // that half is **bounded** — not closed — by `justrdp::egfx` refusing a rectangle larger
        // than any admissible surface before it reaches any codec. A magnitude comparison here
        // would reach it too, so the reason it is not here is ownership rather than visibility:
        // the number that would make such a cap principled is `MAX_TOTAL_SURFACE_BYTES`, which
        // belongs to the surface model and not to a codec. Keeping the two separate is
        // deliberate — this is the totality
        // [ADR-0012](../../../../docs/adr/0012-consumption-site-totality.md) §1 requires of a
        // `pub fn`'s own signature, that is reachability.
        let out_len = w
            .checked_mul(h)
            .and_then(|n| n.checked_mul(4))
            // `isize::MAX`, not `usize::MAX` — see `crate::allocatable`, which is the family's
            // one answer to that threshold. Measured on i686: `40000 x 20000 x 4` is
            // 3_200_000_000, passes `checked_mul`, and then panics with *capacity overflow*.
            .and_then(crate::allocatable)
            .ok_or(RfxError::DimensionsOverflow { width, height })?;
        // Before the parse, not after it. The sibling codecs check their dimensions first
        // (`planar.rs`, `nscodec.rs`) and the reason is measurable here: behind `decode_all`,
        // this arm is reachable only by a payload that parses as a TILESET, which random bytes
        // never are — so the no-panic property below could not drive it at all. Measured both
        // ways; see that property's note.
        let messages = rfx::decode_all(data)?;

        let mut out: Option<Vec<u8>> = None;
        // The clip region in force for the current frame: `None` until a TS_RFX_REGION
        // arrives (clip to the full rectangle), then that region's rects. A region with
        // numRects==0 means the *whole surface*, not an empty clip ([MS-RDPRFX] 2.2.2.3.3),
        // so it is materialized as a single (0,0,width,height) rect below.
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
                RfxMessage::Region(rects) => {
                    // numRects==0 means the full surface, not an empty clip: materialize the
                    // (0,0,width,height) rect FreeRDP fabricates ([MS-RDPRFX] 2.2.2.3.3).
                    region = Some(if rects.is_empty() {
                        vec![RfxRect {
                            x: 0,
                            y: 0,
                            width,
                            height,
                        }]
                    } else {
                        rects.clone()
                    });
                }
                RfxMessage::TileSet(tileset) => {
                    if self.video_mode {
                        return Err(RfxError::VideoMode);
                    }
                    let out = out.get_or_insert_with(|| opaque_black(out_len));
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

/// Takes the byte count rather than the dimensions, so the caller's `checked_mul` is the only
/// place the product is formed and this function has no arithmetic left to get wrong.
fn opaque_black(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for px in out.as_chunks_mut::<4>().0 {
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
        // The parser validated every index against the table. The shift table is derived and
        // validated before a coefficient is touched (ADR-0012 §4), which is what leaves
        // `dequantize` itself infallible.
        let shifts = quant::shifts(&quants[usize::from(quant_idx)])?;
        rlgr::decode(entropy, data, component)?;
        quant::ll3_delta_decode(&mut component[quant::LL3_OFFSET..]);
        quant::dequantize(component, &shifts);
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
    use proptest::prelude::*;

    proptest! {
        // ADR-0008 / issue #97 — the no-panic robustness property. `RfxError`'s contract says
        // malformed input is always a typed error, never a panic — and `decode_to_rgba` is the
        // top-level WTS1 entry, so this one property covers the whole inverse pipeline (TS_RFX
        // block parse → RLGR entropy → LL3 delta → dequant → inverse DWT → ICT) from raw bytes.
        // `data` is the unbounded, attacker-controlled blob, so it is fully arbitrary.
        //
        // **The dimension arms used to read `0u16..=128`, on the rationale that width/height
        // "arrive from fixed u16 destination-rect fields, never the stream". That rationale was
        // false and it hid #263.** A `RDPGFX_RECT16` *is* a stream field — `[MS-RDPEGFX]` 2.2.1.2
        // bounds it at `u16` and states no maximum — so being a `u16` bounds these at 65535, not
        // at 128, and the overflow they are now expected to refuse needs roughly 32768. A
        // generator narrowed to a range no parser enforces asserts nothing about the reject arm,
        // which is #211's `nscodec` finding on the other axis (there: narrowed to a range the
        // parser *did* enforce). Weighted rather than replaced, so the ordinary small-rectangle
        // path stays the common case and the reject arm is still driven — the shape #230
        // settled for `pointer`.
        //
        // Measured rather than asserted, with the dimension guard removed:
        //
        // | generator | i686 |
        // |---|---|
        // | widened, as below | **RED** |
        // | the old `0..=128` | green |
        //
        // **And the widening only earns that because the guard was moved ahead of
        // `decode_all`.** Behind the parse it was green either way: random bytes never form a
        // TILESET, so no generator could drive it. Two changes were needed and the measurement
        // is what separated them — a widened generator alone would have been machinery that
        // reads as coverage.
        //
        // Residue, stated rather than left implicit: on a **64-bit** target the widened arms
        // refuse nothing, because 65535 x 65535 x 4 fits. A case that reached a valid TILESET
        // there would allocate 16 GiB rather than fail — unreachable by chance for the same
        // reason as above, and bounded a layer out in `justrdp::egfx`, not here. What this
        // property still cannot reach on any target is `opaque_black` itself; the directed test
        // above is what covers that.
        //
        // A fresh decoder per case keeps each run independent of the persisted video-mode verdict.
        // Reaching the end without unwinding IS the assertion — proptest fails (and shrinks to a
        // minimal counterexample) on any panic / arithmetic overflow / OOB.
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn decode_to_rgba_never_panics_on_arbitrary_input(
            width in prop_oneof![6 => 0u16..=128, 2 => 60_000u16..=u16::MAX, 1 => any::<u16>()],
            height in prop_oneof![6 => 0u16..=128, 2 => 60_000u16..=u16::MAX, 1 => any::<u16>()],
            data in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = RemoteFx::new().decode_to_rgba(&data, width, height);
        }
    }

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

    /// A `destRect` is bounded by `u16` and by nothing else — `[MS-RDPEGFX]` 2.2.1.2 states no
    /// maximum and no non-zero requirement — and 2.2.2.1 makes it *"the dimensions of the bitmap
    /// data encapsulated in the bitmapData field"*, so it sizes this function's output directly.
    /// A **93-byte** tileset therefore declares 65535 x 65535 x 4 = 17_179_344_900 bytes of it.
    /// Both targets were measured before this guard existed (#263), by a throwaway probe calling
    /// this function with that payload:
    ///
    /// | target | before |
    /// |---|---|
    /// | `i686-pc-windows-msvc` | panic, *attempt to multiply with overflow*, at `opaque_black` |
    /// | `x86_64-pc-windows-msvc` | `Ok(Some(17_179_344_900))` — 16 GiB allocated, 18.9 s, no error |
    ///
    /// Target-gated like its four siblings (`color`, `planar`, `pointer`, `rle`): on 64-bit the
    /// product does not overflow, so `checked_mul` has nothing to refuse. **That is the finding
    /// rather than a limitation of the test** — the 64-bit row is closed one layer out, by
    /// `justrdp::egfx` bounding the rectangle itself, because no arithmetic guard here can see a
    /// multiplication that fits. What this half owns is the obligation
    /// [ADR-0012](../../../../docs/adr/0012-consumption-site-totality.md) §1 puts on a `pub fn`
    /// whose own signature admits the value, whatever its caller happens to guarantee.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn a_rect_whose_rgba_cannot_be_addressed_is_a_typed_error_not_a_panic() {
        let frame = stream(&[(0, 0, 64, 64)], &[(0, 0, vec![0x00; 8])]);
        assert_eq!(
            RemoteFx::new().decode_to_rgba(&frame, u16::MAX, u16::MAX),
            Err(RfxError::DimensionsOverflow {
                width: u16::MAX,
                height: u16::MAX,
            })
        );
        // The second ceiling, and the one a `checked_mul` alone does not reach: 40000 x 20000 x 4
        // is 3_200_000_000 — under `usize::MAX` on this target, over `isize::MAX`, and therefore
        // a *capacity overflow* panic inside `Vec` rather than an allocation. Measured that way
        // before the `.filter`. The first version of this test asserted nothing here and said
        // the boundary "would fail for a reason that has nothing to do with the guard"; the
        // reason had everything to do with the guard, which was written against the wrong
        // ceiling.
        assert_eq!(
            RemoteFx::new().decode_to_rgba(&frame, 40_000, 20_000),
            Err(RfxError::DimensionsOverflow {
                width: 40_000,
                height: 20_000,
            })
        );
        // And it must not over-refuse.
        assert!(RemoteFx::new().decode_to_rgba(&frame, 64, 64).is_ok());
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
    fn an_empty_region_paints_the_full_surface() {
        // TS_RFX_REGION with numRects==0 means the whole surface, not an empty clip
        // ([MS-RDPRFX] 2.2.2.3.3; FreeRDP rfx.c: numRects<1 => rect (0,0,width,height)).
        // A single all-zero tile must therefore paint every pixel through the ICT — being
        // masked out would reintroduce the black-region symptom the RemoteFX work removed.
        let frame = stream(&[], &[(0, 0, vec![0x00; 8])]);
        let mut decoder = RemoteFx::new();
        let rgba = decoder
            .decode_to_rgba(&frame, 64, 64)
            .expect("valid stream")
            .expect("a tileset paints");
        assert_eq!(rgba.len(), 64 * 64 * 4);
        // The decoded zero-spectrum value (not the opaque-black init) must appear — proving the
        // tile painted rather than being clipped away by an empty region.
        let decoded = &rgba[..4];
        assert_ne!(
            decoded,
            &[0u8, 0, 0, 255][..],
            "empty region painted nothing"
        );
        // A pixel deep inside the tile equals the decoded value — full-surface paint, not a
        // partial/empty clip.
        let deep = &rgba[(40 * 64 + 40) * 4..(40 * 64 + 40) * 4 + 4];
        assert_eq!(deep, decoded, "empty region did not paint the full surface");
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
