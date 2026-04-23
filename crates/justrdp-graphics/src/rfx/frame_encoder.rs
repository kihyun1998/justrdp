#![forbid(unsafe_code)]

//! RFX frame-level server encoder -- composes the wire blocks from
//! [`super::wire`] into a single byte stream ready to drop into a
//! `TS_BITMAP_DATA_EX.bitmap_data` payload.
//!
//! ## Responsibility split
//!
//! - [`super::wire`] -- per-block PDU encode/decode + framing constants.
//! - [`super::RfxEncoder`] -- per-tile codec pipeline (BGRA → YCbCr →
//!   DWT → quantize → subband → RLGR).
//! - This module -- frame-level glue: monotonic `frame_id`, image-mode
//!   handshake, and the screen-rect → tile-grid partitioning helper.
//!
//! ## Wire layout produced by [`RfxFrameEncoder::encode_frame`]
//!
//! Image mode (CODEC_MODE_IMAGE) requires the four handshake blocks to
//! precede every encoded frame so the receiver can decode the frame in
//! isolation (MS-RDPRFX 2.2.2.2.4 Remarks). The output of one
//! `encode_frame` call is therefore the concatenation:
//!
//! ```text
//! Sync || CodecVersions || Channels || Context
//!      || FrameBegin    || Region   || TileSet || FrameEnd
//! ```
//!
//! The caller drops the resulting bytes into one
//! `BitmapDataEx::bitmap_data` field inside a `SetSurfaceBitsCmd`
//! covering the full screen rect (or, in §11.2b-3, into an EGFX
//! `WireToSurface1` payload).

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Encode, EncodeError, EncodeResult, WriteCursor};

use super::quant::CodecQuant;
use super::rlgr::RlgrMode;
use super::wire::{
    RfxChannelEntry, RfxChannels, RfxCodecVersions, RfxContext, RfxFrameBegin, RfxFrameEnd,
    RfxProperties, RfxRect, RfxRegion, RfxSync, RfxTileSet, RfxTileWire, CHANNEL_ID_DATA,
    RFX_MAX_CHANNEL_HEIGHT, RFX_MAX_CHANNEL_WIDTH, RFX_MIN_CHANNEL_HEIGHT, RFX_MIN_CHANNEL_WIDTH,
};

/// RFX tile dimension. The codec is tile-fixed; a frame is a grid of
/// 64×64 tiles aligned to the screen origin.
pub const RFX_TILE_SIZE: u16 = 64;

// ── Progressive quality scheduling ──────────────────────────────────

/// Per-tile quality / inclusion decision returned by a
/// [`ProgressiveQualityScheduler`].
///
/// In §11.2b-4 the scheduler is a pure include/exclude gate on top of
/// the single-pass full-quality encoder -- the only currently-defined
/// values are `Skip` (drop the tile from the emitted TileSet) and
/// `Full` (encode at full quality). True multi-pass progressive RFX
/// (gradual refinement of the same tile across frames) is left for a
/// future expansion of this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileQuality {
    /// Drop this tile -- it will not appear in the emitted
    /// `WBT_TILESET`. Use this for delta frames where unchanged tiles
    /// can be elided.
    Skip,
    /// Encode this tile at full quality (the only mode the current
    /// encoder supports).
    Full,
}

/// Caller-supplied policy that decides per-tile inclusion / quality
/// for each frame.
///
/// Receives `frame_id` so schedulers can implement frame-cadence
/// strategies (e.g. "send every tile every 30th frame, otherwise only
/// dirty tiles").
pub trait ProgressiveQualityScheduler {
    /// Decide whether `(x_idx, y_idx)` should be included in the
    /// frame keyed by `frame_id`, and at what quality.
    fn quality_for_tile(
        &mut self,
        frame_id: u32,
        x_idx: u16,
        y_idx: u16,
    ) -> TileQuality;
}

/// Scheduler that always returns [`TileQuality::Full`] -- the implicit
/// default behavior of [`RfxFrameEncoder::encode_frame`].
#[derive(Debug, Clone, Copy, Default)]
pub struct FullQualityScheduler;

impl ProgressiveQualityScheduler for FullQualityScheduler {
    fn quality_for_tile(
        &mut self,
        _frame_id: u32,
        _x_idx: u16,
        _y_idx: u16,
    ) -> TileQuality {
        TileQuality::Full
    }
}

// ── Tile partitioning helper ────────────────────────────────────────

/// Partition a `width × height` screen rectangle into the
/// `(x_idx, y_idx)` indices of every 64×64 tile that overlaps it.
///
/// The tile grid is anchored at `(0, 0)`; the rightmost / bottom row
/// of tiles may extend past the screen rectangle (the codec encodes
/// the full 64×64 tile and the receiver clips). Returns an empty
/// vector when either dimension is `0`.
///
/// `(x_idx, y_idx)` are tile coordinates (pixel position is
/// `(x_idx * 64, y_idx * 64)`). Both fit in a `u16`: spec channel
/// dimensions are at most 4096×2048 ⇒ 64×32 tiles ⇒ both indices fit
/// in a `u8`. The `u16` return type matches [`RfxTileWire::x_idx`] /
/// [`RfxTileWire::y_idx`] so callers can plug values directly.
pub fn partition_screen_tiles(width: u16, height: u16) -> Vec<(u16, u16)> {
    if width == 0 || height == 0 {
        return Vec::new();
    }
    let tiles_x = width.div_ceil(RFX_TILE_SIZE);
    let tiles_y = height.div_ceil(RFX_TILE_SIZE);
    let mut out = Vec::with_capacity(usize::from(tiles_x) * usize::from(tiles_y));
    for y in 0..tiles_y {
        for x in 0..tiles_x {
            out.push((x, y));
        }
    }
    out
}

// ── Frame encoder state ─────────────────────────────────────────────

/// State of the [`RfxFrameEncoder`]. The state is informational --
/// every method is callable in any state and the encoder transitions
/// implicitly on `handshake_bytes` / `encode_frame`. It is exposed for
/// drivers that want to log or assert on session progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfxEncoderState {
    /// No bytes have been emitted yet.
    Init,
    /// `handshake_bytes()` was called explicitly and the caller is
    /// expected to send the returned bytes once. Subsequent
    /// `encode_frame` calls in image mode still prepend the handshake
    /// per spec; this state is informational only.
    HandshakeIssued,
    /// At least one `encode_frame` call has completed.
    FrameIssued,
}

// ── RfxFrameEncoder ─────────────────────────────────────────────────

/// Server-side RFX frame composer.
///
/// Holds the channel dimensions and entropy mode negotiated at session
/// start, plus a monotonic `frame_id` counter that wraps on overflow.
/// Image-mode is the only mode currently implemented (handshake blocks
/// are emitted with every frame).
#[derive(Debug, Clone)]
pub struct RfxFrameEncoder {
    state: RfxEncoderState,
    entropy: RlgrMode,
    width: i16,
    height: i16,
    next_frame_id: u32,
}

impl RfxFrameEncoder {
    /// Construct a new encoder for a single-channel session.
    ///
    /// `width` and `height` are the channel dimensions (typically the
    /// full screen size). They are validated against the
    /// MS-RDPRFX 2.2.2.1.3 SHOULD ranges
    /// (`width ∈ [1, 4096]`, `height ∈ [1, 2048]`); out-of-range
    /// values return [`EncodeError`].
    pub fn new(width: i16, height: i16, entropy: RlgrMode) -> EncodeResult<Self> {
        if width < RFX_MIN_CHANNEL_WIDTH || width > RFX_MAX_CHANNEL_WIDTH {
            return Err(EncodeError::other(
                "RfxFrameEncoder",
                "width out of MS-RDPRFX 2.2.2.1.3 range [1, 4096]",
            ));
        }
        if height < RFX_MIN_CHANNEL_HEIGHT || height > RFX_MAX_CHANNEL_HEIGHT {
            return Err(EncodeError::other(
                "RfxFrameEncoder",
                "height out of MS-RDPRFX 2.2.2.1.3 range [1, 2048]",
            ));
        }
        Ok(Self {
            state: RfxEncoderState::Init,
            entropy,
            width,
            height,
            next_frame_id: 0,
        })
    }

    /// Current state (informational).
    pub fn state(&self) -> RfxEncoderState {
        self.state
    }

    /// Negotiated entropy coder.
    pub fn entropy(&self) -> RlgrMode {
        self.entropy
    }

    /// Channel dimensions as `(width, height)`.
    pub fn channel_size(&self) -> (i16, i16) {
        (self.width, self.height)
    }

    /// `frame_id` that the next [`encode_frame`](Self::encode_frame)
    /// call will emit. Returns `0` before any frame has been encoded.
    pub fn next_frame_id(&self) -> u32 {
        self.next_frame_id
    }

    /// Emit the four handshake blocks (Sync + CodecVersions + Channels
    /// + Context) as a single concatenated byte stream.
    ///
    /// In image mode, [`encode_frame`](Self::encode_frame) already
    /// prepends these blocks to every frame -- this entry point is
    /// only useful for drivers that want to send the handshake once at
    /// session start (e.g. a hypothetical future video-mode codepath).
    pub fn handshake_bytes(&mut self) -> EncodeResult<Vec<u8>> {
        let bytes = build_handshake(self.width, self.height, self.entropy)?;
        self.state = RfxEncoderState::HandshakeIssued;
        Ok(bytes)
    }

    /// Encode one full frame at full quality (every supplied tile is
    /// included verbatim).
    ///
    /// `rects` are the destination rectangles; `numRects = 0` is wire-
    /// legal and the receiver synthesises a full-channel rect.
    /// `quant_vals` is the shared quant table referenced by every
    /// tile's `quant_idx_*`. `tiles` carry pre-encoded RLGR component
    /// streams from [`super::RfxEncoder::encode_tile`].
    ///
    /// The internal `frame_id` counter increments after every
    /// successful call (wrapping at `u32::MAX`).
    ///
    /// For per-tile inclusion decisions (delta frames, throttled
    /// updates, etc.), use
    /// [`encode_frame_with_scheduler`](Self::encode_frame_with_scheduler).
    pub fn encode_frame(
        &mut self,
        rects: &[RfxRect],
        quant_vals: Vec<CodecQuant>,
        tiles: Vec<RfxTileWire>,
    ) -> EncodeResult<Vec<u8>> {
        self.encode_frame_with_scheduler(
            rects,
            quant_vals,
            tiles,
            &mut FullQualityScheduler,
        )
    }

    /// Encode one frame, consulting `scheduler` to decide whether to
    /// include each tile.
    ///
    /// Tiles for which the scheduler returns [`TileQuality::Skip`] are
    /// dropped before the TileSet is built; the resulting `numTiles`
    /// reflects only the kept tiles. The handshake blocks and frame
    /// envelope (`FrameBegin` / `Region` / `FrameEnd`) are emitted
    /// unconditionally so the receiver still sees a well-formed frame
    /// even when every tile is skipped.
    ///
    /// `frame_id` (the value handed to the scheduler) is the same
    /// monotonic counter used by [`encode_frame`](Self::encode_frame);
    /// it advances after a successful call.
    pub fn encode_frame_with_scheduler(
        &mut self,
        rects: &[RfxRect],
        quant_vals: Vec<CodecQuant>,
        tiles: Vec<RfxTileWire>,
        scheduler: &mut dyn ProgressiveQualityScheduler,
    ) -> EncodeResult<Vec<u8>> {
        let frame_id = self.next_frame_id;
        let kept: Vec<RfxTileWire> = tiles
            .into_iter()
            .filter(|t| {
                scheduler.quality_for_tile(frame_id, t.x_idx, t.y_idx) != TileQuality::Skip
            })
            .collect();
        let handshake = build_handshake(self.width, self.height, self.entropy)?;

        let frame_begin = RfxFrameBegin {
            frame_idx: frame_id,
            num_regions: 1,
        };
        let region = RfxRegion {
            rects: rects.to_vec(),
        };
        let tileset = RfxTileSet {
            properties: RfxProperties::image(self.entropy),
            quant_vals,
            tiles: kept,
        };
        let frame_end = RfxFrameEnd;

        let total = handshake.len()
            + frame_begin.size()
            + region.size()
            + tileset.size()
            + frame_end.size();
        let mut buf = vec![0u8; total];
        {
            let mut c = WriteCursor::new(&mut buf);
            // handshake bytes are already serialised; copy verbatim.
            c.write_slice(&handshake, "RfxFrameEncoder::handshake")?;
            frame_begin.encode(&mut c)?;
            region.encode(&mut c)?;
            tileset.encode(&mut c)?;
            frame_end.encode(&mut c)?;
        }
        self.next_frame_id = self.next_frame_id.wrapping_add(1);
        self.state = RfxEncoderState::FrameIssued;
        Ok(buf)
    }
}

/// Serialise the four handshake blocks (Sync + CodecVersions +
/// Channels + Context) into a single byte vector.
fn build_handshake(width: i16, height: i16, entropy: RlgrMode) -> EncodeResult<Vec<u8>> {
    let sync = RfxSync;
    let versions = RfxCodecVersions;
    let channels = RfxChannels {
        channels: vec![RfxChannelEntry {
            channel_id: CHANNEL_ID_DATA,
            width,
            height,
        }],
    };
    let ctx = RfxContext::image(entropy);

    let total = sync.size() + versions.size() + channels.size() + ctx.size();
    let mut buf = vec![0u8; total];
    {
        let mut c = WriteCursor::new(&mut buf);
        sync.encode(&mut c)?;
        versions.encode(&mut c)?;
        channels.encode(&mut c)?;
        ctx.encode(&mut c)?;
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_core::{Decode, ReadCursor};

    use super::super::wire::{
        RFX_BLOCK_HEADER_SIZE, RFX_CODEC_CHANNEL_HEADER_SIZE, RFX_CODEC_VERSIONS_SIZE,
        RFX_CONTEXT_SIZE, RFX_FRAME_BEGIN_SIZE, RFX_FRAME_END_SIZE, RFX_SYNC_SIZE,
    };

    // ── partition_screen_tiles ───────────────────────────────────

    #[test]
    fn partition_zero_dim_returns_empty() {
        assert!(partition_screen_tiles(0, 100).is_empty());
        assert!(partition_screen_tiles(100, 0).is_empty());
        assert!(partition_screen_tiles(0, 0).is_empty());
    }

    #[test]
    fn partition_exact_multiple_of_tile_size() {
        let p = partition_screen_tiles(128, 64);
        assert_eq!(p, vec![(0, 0), (1, 0)]);
    }

    #[test]
    fn partition_rounds_up_partial_tile() {
        // 100x70 → 2 tiles wide, 2 tiles tall (rightmost / bottom row
        // extend past the screen and the receiver clips).
        let p = partition_screen_tiles(100, 70);
        assert_eq!(p, vec![(0, 0), (1, 0), (0, 1), (1, 1)]);
    }

    #[test]
    fn partition_single_pixel_makes_one_tile() {
        assert_eq!(partition_screen_tiles(1, 1), vec![(0, 0)]);
    }

    #[test]
    fn partition_full_hd_screen_count() {
        // 1920 x 1080 → 30 x 17 tiles = 510.
        let p = partition_screen_tiles(1920, 1080);
        assert_eq!(p.len(), 30 * 17);
        assert_eq!(*p.first().unwrap(), (0, 0));
        assert_eq!(*p.last().unwrap(), (29, 16));
    }

    // ── RfxFrameEncoder constructor ──────────────────────────────

    #[test]
    fn new_rejects_out_of_range_dimensions() {
        assert!(RfxFrameEncoder::new(0, 1080, RlgrMode::Rlgr3).is_err());
        assert!(RfxFrameEncoder::new(1920, 0, RlgrMode::Rlgr3).is_err());
        assert!(RfxFrameEncoder::new(-1, 1080, RlgrMode::Rlgr3).is_err());
        assert!(RfxFrameEncoder::new(4097, 1080, RlgrMode::Rlgr3).is_err());
        assert!(RfxFrameEncoder::new(1920, 2049, RlgrMode::Rlgr3).is_err());
    }

    #[test]
    fn new_accepts_boundary_dimensions() {
        assert!(RfxFrameEncoder::new(1, 1, RlgrMode::Rlgr1).is_ok());
        assert!(RfxFrameEncoder::new(4096, 2048, RlgrMode::Rlgr3).is_ok());
    }

    #[test]
    fn new_initial_state_and_accessors() {
        let e = RfxFrameEncoder::new(1920, 1080, RlgrMode::Rlgr3).unwrap();
        assert_eq!(e.state(), RfxEncoderState::Init);
        assert_eq!(e.entropy(), RlgrMode::Rlgr3);
        assert_eq!(e.channel_size(), (1920, 1080));
        assert_eq!(e.next_frame_id(), 0);
    }

    // ── handshake_bytes ──────────────────────────────────────────

    #[test]
    fn handshake_bytes_size_and_blocks_in_order() {
        let mut e = RfxFrameEncoder::new(1920, 1080, RlgrMode::Rlgr3).unwrap();
        let bytes = e.handshake_bytes().unwrap();
        let expected = RFX_SYNC_SIZE
            + RFX_CODEC_VERSIONS_SIZE
            + (7 + 5) // Channels: 7 + 1*5
            + RFX_CONTEXT_SIZE;
        assert_eq!(bytes.len(), expected);
        assert_eq!(e.state(), RfxEncoderState::HandshakeIssued);

        // Verify the four blocks decode in order.
        let mut c = ReadCursor::new(&bytes);
        let _sync = RfxSync::decode(&mut c).unwrap();
        let _versions = RfxCodecVersions::decode(&mut c).unwrap();
        let channels = RfxChannels::decode(&mut c).unwrap();
        assert_eq!(channels.channels.len(), 1);
        assert_eq!(channels.channels[0].width, 1920);
        assert_eq!(channels.channels[0].height, 1080);
        let ctx = RfxContext::decode(&mut c).unwrap();
        assert_eq!(ctx.properties.entropy, RlgrMode::Rlgr3);
        assert_eq!(c.remaining(), 0);
    }

    // ── encode_frame ─────────────────────────────────────────────

    fn sample_quant() -> CodecQuant {
        CodecQuant::from_bytes(&[0x66, 0x66, 0x66, 0x66, 0x66])
    }

    fn sample_tile(x_idx: u16, y_idx: u16) -> RfxTileWire {
        RfxTileWire {
            quant_idx_y: 0,
            quant_idx_cb: 0,
            quant_idx_cr: 0,
            x_idx,
            y_idx,
            y_data: vec![0xAA; 32],
            cb_data: vec![0xBB; 32],
            cr_data: vec![0xCC; 32],
        }
    }

    fn parse_frame(bytes: &[u8]) -> (RfxFrameBegin, RfxRegion, RfxTileSet, RfxFrameEnd) {
        let mut c = ReadCursor::new(bytes);
        // Skip handshake.
        let _ = RfxSync::decode(&mut c).unwrap();
        let _ = RfxCodecVersions::decode(&mut c).unwrap();
        let _ = RfxChannels::decode(&mut c).unwrap();
        let _ = RfxContext::decode(&mut c).unwrap();
        // Frame body.
        let fb = RfxFrameBegin::decode(&mut c).unwrap();
        let region = RfxRegion::decode(&mut c).unwrap();
        let tileset = RfxTileSet::decode(&mut c).unwrap();
        let fe = RfxFrameEnd::decode(&mut c).unwrap();
        assert_eq!(c.remaining(), 0);
        (fb, region, tileset, fe)
    }

    #[test]
    fn encode_frame_image_mode_prepends_handshake() {
        let mut e = RfxFrameEncoder::new(1920, 1080, RlgrMode::Rlgr3).unwrap();
        let bytes = e
            .encode_frame(&[], vec![sample_quant()], vec![sample_tile(0, 0)])
            .unwrap();

        // Handshake blocks must precede the frame body.
        let mut c = ReadCursor::new(&bytes);
        RfxSync::decode(&mut c).unwrap();
        RfxCodecVersions::decode(&mut c).unwrap();
        RfxChannels::decode(&mut c).unwrap();
        RfxContext::decode(&mut c).unwrap();
        // Frame body next.
        let fb = RfxFrameBegin::decode(&mut c).unwrap();
        assert_eq!(fb.frame_idx, 0);
        assert_eq!(fb.num_regions, 1);
    }

    #[test]
    fn encode_frame_increments_frame_id() {
        let mut e = RfxFrameEncoder::new(800, 600, RlgrMode::Rlgr1).unwrap();
        for expected_id in [0u32, 1, 2] {
            assert_eq!(e.next_frame_id(), expected_id);
            let bytes = e
                .encode_frame(&[], vec![sample_quant()], vec![sample_tile(0, 0)])
                .unwrap();
            let (fb, ..) = parse_frame(&bytes);
            assert_eq!(fb.frame_idx, expected_id);
        }
        assert_eq!(e.next_frame_id(), 3);
        assert_eq!(e.state(), RfxEncoderState::FrameIssued);
    }

    #[test]
    fn encode_frame_id_wraps_at_u32_max() {
        let mut e = RfxFrameEncoder::new(64, 64, RlgrMode::Rlgr1).unwrap();
        e.next_frame_id = u32::MAX;
        let bytes = e
            .encode_frame(&[], vec![sample_quant()], vec![sample_tile(0, 0)])
            .unwrap();
        let (fb, ..) = parse_frame(&bytes);
        assert_eq!(fb.frame_idx, u32::MAX);
        assert_eq!(e.next_frame_id(), 0);
    }

    #[test]
    fn encode_frame_handshake_carries_current_dimensions() {
        let mut e = RfxFrameEncoder::new(2560, 1440, RlgrMode::Rlgr3).unwrap();
        let bytes = e
            .encode_frame(&[], vec![sample_quant()], vec![sample_tile(0, 0)])
            .unwrap();
        let mut c = ReadCursor::new(&bytes);
        RfxSync::decode(&mut c).unwrap();
        RfxCodecVersions::decode(&mut c).unwrap();
        let channels = RfxChannels::decode(&mut c).unwrap();
        assert_eq!(channels.channels[0].width, 2560);
        assert_eq!(channels.channels[0].height, 1440);
    }

    #[test]
    fn encode_frame_with_multiple_rects_and_tiles() {
        let mut e = RfxFrameEncoder::new(640, 480, RlgrMode::Rlgr3).unwrap();
        let rects = vec![
            RfxRect { x: 0, y: 0, width: 64, height: 64 },
            RfxRect { x: 64, y: 0, width: 64, height: 64 },
            RfxRect { x: 0, y: 64, width: 64, height: 64 },
        ];
        let tiles = vec![
            sample_tile(0, 0),
            sample_tile(1, 0),
            sample_tile(0, 1),
        ];
        let bytes = e
            .encode_frame(&rects, vec![sample_quant()], tiles)
            .unwrap();
        let (_, region, tileset, _) = parse_frame(&bytes);
        assert_eq!(region.rects.len(), 3);
        assert_eq!(tileset.tiles.len(), 3);
        assert_eq!(tileset.quant_vals.len(), 1);
    }

    #[test]
    fn encode_frame_empty_rects_and_tiles_still_emits_full_envelope() {
        // numRects = 0 and numTiles = 0 are wire-legal; the receiver
        // synthesises a full-channel rect and skips tile decode.
        let mut e = RfxFrameEncoder::new(800, 600, RlgrMode::Rlgr1).unwrap();
        let bytes = e.encode_frame(&[], vec![], vec![]).unwrap();
        let (fb, region, tileset, _fe) = parse_frame(&bytes);
        assert_eq!(fb.frame_idx, 0);
        assert_eq!(region.rects.len(), 0);
        assert_eq!(tileset.tiles.len(), 0);
        assert_eq!(tileset.quant_vals.len(), 0);
    }

    #[test]
    fn encode_frame_rejects_quant_idx_out_of_range() {
        // tile references quant idx 1 but quant_vals has only 1 entry
        // (idx 0 is the only valid index).
        let mut e = RfxFrameEncoder::new(800, 600, RlgrMode::Rlgr3).unwrap();
        let mut bad_tile = sample_tile(0, 0);
        bad_tile.quant_idx_y = 1;
        let res = e.encode_frame(&[], vec![sample_quant()], vec![bad_tile]);
        assert!(res.is_err());
    }

    #[test]
    fn encode_frame_uses_image_mode_properties_in_tileset() {
        let mut e = RfxFrameEncoder::new(800, 600, RlgrMode::Rlgr1).unwrap();
        let bytes = e
            .encode_frame(&[], vec![sample_quant()], vec![sample_tile(0, 0)])
            .unwrap();
        let (.., tileset, _) = parse_frame(&bytes);
        assert_eq!(tileset.properties.entropy, RlgrMode::Rlgr1);
    }

    #[test]
    fn state_transitions_init_handshake_issued_frame_issued_in_sequence() {
        let mut e = RfxFrameEncoder::new(800, 600, RlgrMode::Rlgr3).unwrap();
        assert_eq!(e.state(), RfxEncoderState::Init);
        let _ = e.handshake_bytes().unwrap();
        assert_eq!(e.state(), RfxEncoderState::HandshakeIssued);
        // encode_frame still prepends handshake even after explicit
        // handshake_bytes() call -- image mode is independent of state.
        let bytes = e
            .encode_frame(&[], vec![sample_quant()], vec![sample_tile(0, 0)])
            .unwrap();
        assert_eq!(e.state(), RfxEncoderState::FrameIssued);
        // Confirm the frame still starts with a Sync block.
        let mut c = ReadCursor::new(&bytes);
        assert!(RfxSync::decode(&mut c).is_ok());
    }

    // ── ProgressiveQualityScheduler ──────────────────────────────

    /// Test scheduler that drops tiles whose `(x_idx, y_idx)` matches
    /// any in `skip_tiles`.
    struct SkipListScheduler {
        skip_tiles: Vec<(u16, u16)>,
        observed_frame_ids: Vec<u32>,
    }

    impl SkipListScheduler {
        fn new(skip_tiles: Vec<(u16, u16)>) -> Self {
            Self {
                skip_tiles,
                observed_frame_ids: Vec::new(),
            }
        }
    }

    impl ProgressiveQualityScheduler for SkipListScheduler {
        fn quality_for_tile(
            &mut self,
            frame_id: u32,
            x_idx: u16,
            y_idx: u16,
        ) -> TileQuality {
            self.observed_frame_ids.push(frame_id);
            if self.skip_tiles.contains(&(x_idx, y_idx)) {
                TileQuality::Skip
            } else {
                TileQuality::Full
            }
        }
    }

    #[test]
    fn full_quality_scheduler_keeps_every_tile() {
        let mut e = RfxFrameEncoder::new(800, 600, RlgrMode::Rlgr3).unwrap();
        let bytes = e
            .encode_frame_with_scheduler(
                &[],
                vec![sample_quant()],
                vec![sample_tile(0, 0), sample_tile(1, 0), sample_tile(0, 1)],
                &mut FullQualityScheduler,
            )
            .unwrap();
        let (.., tileset, _) = parse_frame(&bytes);
        assert_eq!(tileset.tiles.len(), 3);
    }

    #[test]
    fn scheduler_skip_drops_those_tiles_only() {
        let mut e = RfxFrameEncoder::new(800, 600, RlgrMode::Rlgr3).unwrap();
        let mut scheduler = SkipListScheduler::new(vec![(1, 0), (0, 1)]);
        let bytes = e
            .encode_frame_with_scheduler(
                &[],
                vec![sample_quant()],
                vec![
                    sample_tile(0, 0),
                    sample_tile(1, 0), // skipped
                    sample_tile(0, 1), // skipped
                    sample_tile(1, 1),
                ],
                &mut scheduler,
            )
            .unwrap();
        let (.., tileset, _) = parse_frame(&bytes);
        assert_eq!(tileset.tiles.len(), 2);
        let kept_indices: Vec<(u16, u16)> = tileset
            .tiles
            .iter()
            .map(|t| (t.x_idx, t.y_idx))
            .collect();
        assert_eq!(kept_indices, vec![(0, 0), (1, 1)]);
    }

    #[test]
    fn scheduler_skip_all_emits_empty_tileset_but_full_envelope() {
        let mut e = RfxFrameEncoder::new(800, 600, RlgrMode::Rlgr1).unwrap();
        let mut scheduler = SkipListScheduler::new(vec![(0, 0), (1, 0)]);
        let bytes = e
            .encode_frame_with_scheduler(
                &[],
                vec![sample_quant()],
                vec![sample_tile(0, 0), sample_tile(1, 0)],
                &mut scheduler,
            )
            .unwrap();
        let (fb, region, tileset, _fe) = parse_frame(&bytes);
        // All four envelope blocks (handshake + frame begin/region/end)
        // are still emitted even with zero tiles.
        assert_eq!(fb.frame_idx, 0);
        assert_eq!(region.rects.len(), 0);
        assert_eq!(tileset.tiles.len(), 0);
    }

    #[test]
    fn scheduler_receives_current_frame_id() {
        let mut e = RfxFrameEncoder::new(800, 600, RlgrMode::Rlgr3).unwrap();
        // Burn a frame to advance the counter.
        e.encode_frame(&[], vec![], vec![]).unwrap();
        assert_eq!(e.next_frame_id(), 1);
        let mut scheduler = SkipListScheduler::new(vec![]);
        e.encode_frame_with_scheduler(
            &[],
            vec![sample_quant()],
            vec![sample_tile(0, 0), sample_tile(1, 0)],
            &mut scheduler,
        )
        .unwrap();
        // Both tile-quality calls saw frame_id == 1.
        assert_eq!(scheduler.observed_frame_ids, vec![1, 1]);
    }

    #[test]
    fn encode_frame_routes_through_full_quality_scheduler() {
        // The `encode_frame` convenience MUST behave identically to
        // `encode_frame_with_scheduler(.., FullQualityScheduler)`.
        let mut e1 = RfxFrameEncoder::new(800, 600, RlgrMode::Rlgr3).unwrap();
        let mut e2 = RfxFrameEncoder::new(800, 600, RlgrMode::Rlgr3).unwrap();
        let tiles = vec![sample_tile(0, 0), sample_tile(1, 1)];
        let a = e1
            .encode_frame(&[], vec![sample_quant()], tiles.clone())
            .unwrap();
        let b = e2
            .encode_frame_with_scheduler(
                &[],
                vec![sample_quant()],
                tiles,
                &mut FullQualityScheduler,
            )
            .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn encode_frame_end_to_end_with_real_rfx_encoder() {
        // Drive the full server pipeline: a 64×64 BGRA tile is RLGR-encoded
        // by `RfxEncoder::encode_tile`, wrapped in `RfxTileWire`, and
        // composed into a frame by `RfxFrameEncoder`. The output decodes
        // cleanly through the wire-level decoders.
        use super::super::RfxEncoder;
        use super::super::TILE_SIZE;

        let mut bgra = vec![0u8; TILE_SIZE * TILE_SIZE * 4];
        for i in 0..(TILE_SIZE * TILE_SIZE) {
            bgra[i * 4] = (i & 0xFF) as u8; // B
            bgra[i * 4 + 1] = ((i >> 8) & 0xFF) as u8; // G
            bgra[i * 4 + 2] = ((i / 17) & 0xFF) as u8; // R
            bgra[i * 4 + 3] = 0xFF; // A
        }

        let quant = sample_quant();
        let codec = RfxEncoder::new(RlgrMode::Rlgr3);
        let (y_data, cb_data, cr_data) = codec
            .encode_tile(&bgra, &quant, &quant, &quant)
            .unwrap();

        // Plausibility: each component should produce non-empty RLGR.
        assert!(!y_data.is_empty());
        assert!(!cb_data.is_empty());
        assert!(!cr_data.is_empty());

        let tile = RfxTileWire {
            quant_idx_y: 0,
            quant_idx_cb: 0,
            quant_idx_cr: 0,
            x_idx: 0,
            y_idx: 0,
            y_data,
            cb_data,
            cr_data,
        };

        let mut enc = RfxFrameEncoder::new(64, 64, RlgrMode::Rlgr3).unwrap();
        let bytes = enc
            .encode_frame(
                &[RfxRect { x: 0, y: 0, width: 64, height: 64 }],
                vec![quant],
                vec![tile.clone()],
            )
            .unwrap();

        // Re-decode every block from the wire bytes.
        let (fb, region, tileset, _fe) = parse_frame(&bytes);
        assert_eq!(fb.frame_idx, 0);
        assert_eq!(region.rects.len(), 1);
        assert_eq!(region.rects[0].width, 64);
        assert_eq!(tileset.tiles.len(), 1);
        let decoded_tile = &tileset.tiles[0];
        assert_eq!(decoded_tile, &tile);
        assert_eq!(decoded_tile.x_idx, 0);
        assert_eq!(decoded_tile.y_idx, 0);
        // Quant and properties surface intact.
        assert_eq!(tileset.quant_vals.len(), 1);
        assert_eq!(tileset.properties.entropy, RlgrMode::Rlgr3);
    }

    #[test]
    fn encode_frame_size_matches_header_total_for_minimal_frame() {
        // Reproduce the minimum-size frame and verify the total length
        // matches the sum of the documented per-block sizes.
        let mut e = RfxFrameEncoder::new(64, 64, RlgrMode::Rlgr1).unwrap();
        let bytes = e.encode_frame(&[], vec![], vec![]).unwrap();
        let handshake_total = RFX_SYNC_SIZE
            + RFX_CODEC_VERSIONS_SIZE
            + (7 + 5)
            + RFX_CONTEXT_SIZE;
        let region_total = RFX_CODEC_CHANNEL_HEADER_SIZE + 1 + 2 + 2 + 2; // header + flags + numRects + regionType + numTilesets
        let tileset_total = 22; // RFX_TILESET_FIXED_PREFIX_SIZE
        let frame_body_total = RFX_FRAME_BEGIN_SIZE
            + region_total
            + tileset_total
            + RFX_FRAME_END_SIZE;
        assert_eq!(bytes.len(), handshake_total + frame_body_total);
        // Suppress unused-import warning when only RFX_BLOCK_HEADER_SIZE
        // is needed for documentation parity.
        let _ = RFX_BLOCK_HEADER_SIZE;
    }
}
