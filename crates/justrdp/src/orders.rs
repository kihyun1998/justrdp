//! Drawing orders in the session (`[MS-RDPEGDI]` 3.2.5.1): the Revision 2 bitmap caches the
//! Cache Bitmap orders fill, MemBlt and Mem3Blt painting from them into the framebuffer, and
//! ScrBlt copying within it.
//!
//! Orders are decoded one at a time against the connection's [`OrderHistory`]. An order of a
//! type the history cannot decode ends the update (it has no length to skip by); every order up
//! to it has already been applied.

use crate::framebuffer::{FrameUpdate, Framebuffer};
use crate::session::{charge, decode_bitmap};
use justrdp_codecs::color::{self, Palette};
use justrdp_codecs::rop::{self, Pattern};
use justrdp_pdu::capability::{self, CapabilitySet};
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::orders::{
    self, BITMAPCACHE_WAITING_LIST_INDEX, Bounds, Brush, CacheBitmapRev2, CacheColorTable,
    CacheGlyph, Clip, DrawingOrder, GlyphIndex, Mem3Blt, MemBlt, OrderError, OrderHistory,
    OrdersUpdate, ScrBlt,
};

/// ROP3 SRCCOPY: the source, unchanged.
const SRCCOPY: u8 = 0xCC;
/// ROP3 PATCOPY: the pattern, unchanged.
const PATCOPY: u8 = 0xF0;

/// One cached bitmap, decoded to top-down RGBA.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedBitmap {
    width: u16,
    height: u16,
    rgba: Vec<u8>,
}

/// Why an order was skipped rather than painted (3.2.5.1.1.1 step 4: the order is ignored).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Skip {
    /// Its clip is a rectangle the history lost.
    UnknownClip,
    /// Its cache ID or index is outside the advertised caches.
    CacheOutOfRange,
    /// The entry it names holds no bitmap.
    CacheMiss,
    /// A bitmap of more pixels than its cache's entry, the tile side squared.
    OversizedBitmap,
    /// A brush this session cannot draw: cached, hollow under a ROP that reads the pattern, or
    /// a hatch outside the six.
    UnsupportedBrush,
    /// A DstBlt whose ROP reads the pattern or the source.
    DstBltReadsMore,
    /// A glyph run reached a fragment operation (USE or ADD), and no fragment cache is kept.
    GlyphFragment,
    /// A glyph outside the advertised glyph caches, or larger than its cache's cells.
    UncachedGlyph,
    /// A Cache Color Table entry past the six (2.2.2.2.1.2.4).
    OutsideColorTables,
    /// The update's paint budget is spent.
    OverBudget,
}

/// The connection's drawing-order state: the primary order history, the bitmap caches and which
/// blits were advertised, and the rects of a Frame Marker pair still open. A
/// Deactivation–Reactivation keeps the caches and resets the rest ([`Self::reactivate`]).
#[derive(Debug)]
pub(crate) struct Orders {
    history: OrderHistory,
    /// Each advertised Revision 2 cache, its entries followed by one waiting-list entry.
    caches: Vec<Vec<Option<CachedBitmap>>>,
    /// The ten glyph caches, each the advertised entries, and each one's cell size in bytes.
    glyphs: Vec<(Vec<Option<Glyph>>, usize)>,
    glyph_index: bool,
    dstblt: bool,
    /// PatBlt and OpaqueRect, which one `orderSupport` index negotiates.
    patblt: bool,
    multi_opaque_rect: bool,
    scrblt: bool,
    memblt: bool,
    mem3blt: bool,
    /// A `TS_FRAME_START` arrived and its `TS_FRAME_END` has not.
    in_frame: bool,
    /// The rects painted since that start, in paint order, at most [`MAX_HELD_RECTS`].
    held: Vec<FrameUpdate>,
    /// How many frames a `TS_FRAME_END` closed or a reactivation dropped.
    frames_ended: u64,
}

/// Above this many held rects a frame collapses to their bounding box.
const MAX_HELD_RECTS: usize = 64;

impl Orders {
    /// The order state the advertised capability sets describe.
    pub(crate) fn new(capabilities: &[CapabilitySet]) -> Self {
        let support = capabilities.iter().find_map(|set| match set {
            CapabilitySet::Order(o) => Some(o.order_support),
            _ => None,
        });
        let caches = capabilities
            .iter()
            .find_map(|set| match set {
                CapabilitySet::BitmapCacheRev2(c) => Some(
                    c.cells
                        .iter()
                        .map(|cell| vec![None; cell.entries as usize + 1])
                        .collect(),
                ),
                _ => None,
            })
            .unwrap_or_default();
        let glyphs = capabilities
            .iter()
            .find_map(|set| match set {
                CapabilitySet::GlyphCache(g) if g.glyph_support_level != 0 => Some(
                    g.glyph_cache
                        .iter()
                        .map(|&(entries, cell)| {
                            (vec![None; usize::from(entries)], usize::from(cell))
                        })
                        .collect(),
                ),
                _ => None,
            })
            .unwrap_or_default();
        Self {
            history: OrderHistory::default(),
            caches,
            glyph_index: support.is_some_and(|s| s[capability::ORDER_NEG_INDEX_INDEX] != 0),
            glyphs,
            dstblt: support.is_some_and(|s| s[capability::ORDER_NEG_DSTBLT_INDEX] != 0),
            patblt: support.is_some_and(|s| s[capability::ORDER_NEG_PATBLT_INDEX] != 0),
            multi_opaque_rect: support
                .is_some_and(|s| s[capability::ORDER_NEG_MULTIOPAQUERECT_INDEX] != 0),
            scrblt: support.is_some_and(|s| s[capability::ORDER_NEG_SCRBLT_INDEX] != 0),
            memblt: support.is_some_and(|s| s[capability::ORDER_NEG_MEMBLT_INDEX] != 0),
            mem3blt: support.is_some_and(|s| s[capability::ORDER_NEG_MEM3BLT_INDEX] != 0),
            in_frame: false,
            held: Vec::new(),
            frames_ended: 0,
        }
    }

    /// Forget the primary order history and any frame in flight (a Deactivation–Reactivation).
    pub(crate) fn reactivate(&mut self) {
        self.history = OrderHistory::default();
        if self.in_frame {
            self.frames_ended += 1;
        }
        self.in_frame = false;
        self.held.clear();
    }

    /// Drop the rects held for the frame in flight: the framebuffer they name was replaced. The
    /// frame stays open, so its end still closes it.
    pub(crate) fn discard_held(&mut self) {
        self.held.clear();
    }

    /// Whether a `TS_FRAME_START` is waiting for its `TS_FRAME_END`.
    pub(crate) fn in_frame(&self) -> bool {
        self.in_frame
    }

    /// How many frames a `TS_FRAME_END` closed or a reactivation dropped.
    pub(crate) fn frames_ended(&self) -> u64 {
        self.frames_ended
    }

    /// Hand over the rects held for the frame in flight, which stays open.
    pub(crate) fn release_held(&mut self) -> Vec<FrameUpdate> {
        core::mem::take(&mut self.held)
    }

    /// Hand the rects one order painted to the host now, or hold them for the frame's end.
    fn deliver(&mut self, painted: &mut Vec<FrameUpdate>, frames: &mut Vec<FrameUpdate>) {
        if !self.in_frame {
            frames.append(painted);
            return;
        }
        self.held.append(painted);
        if self.held.len() > MAX_HELD_RECTS {
            let left = self.held.iter().map(|r| r.x).min().unwrap_or(0);
            let top = self.held.iter().map(|r| r.y).min().unwrap_or(0);
            let right = self
                .held
                .iter()
                .map(|r| r.x.saturating_add(r.width))
                .max()
                .unwrap_or(0);
            let bottom = self
                .held
                .iter()
                .map(|r| r.y.saturating_add(r.height))
                .max()
                .unwrap_or(0);
            self.held.clear();
            self.held.push(FrameUpdate {
                x: left,
                y: top,
                width: right - left,
                height: bottom - top,
            });
        }
    }

    /// A Frame Marker: start holding, or release what was held.
    fn frame_marker(&mut self, action: u32, frames: &mut Vec<FrameUpdate>) {
        match action {
            orders::TS_FRAME_START => {
                if self.in_frame {
                    tracing::debug!(target: "rdp_orders", "a frame start inside a frame, continued");
                }
                self.in_frame = true;
            }
            orders::TS_FRAME_END if self.in_frame => {
                self.in_frame = false;
                self.frames_ended += 1;
                frames.append(&mut self.held);
            }
            orders::TS_FRAME_END => {
                tracing::debug!(target: "rdp_orders", "a frame end with no start, ignored");
            }
            action => {
                tracing::debug!(target: "rdp_orders", action, "a Frame Marker action neither starts nor ends, ignored");
            }
        }
    }

    /// Apply one Orders Update, pushing a [`FrameUpdate`] for each order that painted, or, for
    /// an order inside a Frame Marker pair, when the pair ends.
    /// `bits_per_pixel` is the session's color depth, `budget` the decoded bytes this update may
    /// buy. Malformed bytes are an error; anything well formed is applied or skipped.
    pub(crate) fn apply(
        &mut self,
        update: OrdersUpdate<'_>,
        framebuffer: &mut Framebuffer,
        palette: &Palette,
        bits_per_pixel: u16,
        mut budget: usize,
        frames: &mut Vec<FrameUpdate>,
    ) -> Result<(), crate::SessionError> {
        let mut cur = ReadCursor::new(update.order_data, "orderData");
        let mut over_budget = 0usize;
        let mut painted = Vec::new();
        for index in 0..update.number_orders {
            let order = match orders::decode_order(&mut cur, &mut self.history) {
                Ok(order) => order,
                Err(OrderError::Unsupported { class, order_type }) => {
                    tracing::warn!(
                        target: "rdp_orders",
                        ?class,
                        order_type,
                        declared = update.number_orders,
                        applied = index,
                        "a drawing order of a type not decoded; the rest of the update is skipped"
                    );
                    break;
                }
                Err(OrderError::Decode(error)) => return Err(crate::SessionError::Decode(error)),
            };
            let outcome = match order {
                DrawingOrder::CacheBitmapRev2(order) => {
                    self.cache_bitmap(&order, palette, bits_per_pixel, &mut budget)
                }
                DrawingOrder::CacheGlyph(order) => self.cache_glyph(&order, &mut budget),
                DrawingOrder::CacheColorTable(order) => color_table(&order, palette),
                DrawingOrder::GlyphIndex { order, clip } => self.glyph_index(
                    &order,
                    clip,
                    framebuffer,
                    palette,
                    bits_per_pixel,
                    &mut budget,
                    &mut painted,
                ),
                DrawingOrder::DstBlt { order, clip } => {
                    if matches!(order.rop, 0x00 | 0x55 | 0xAA | 0xFF) {
                        let dstblt = Fill {
                            dest: [order.left, order.top, order.width, order.height],
                            rop: order.rop,
                            brush: Pattern::Solid(0),
                            clip,
                        };
                        fill(self.dstblt, dstblt, framebuffer, &mut budget, &mut painted)
                    } else {
                        Err(NotApplied::Skipped(Skip::DstBltReadsMore))
                    }
                }
                DrawingOrder::PatBlt { order, clip } => {
                    let brush = if rop::uses_pattern(order.rop) {
                        pattern(
                            &order.brush,
                            order.fore_color,
                            order.back_color,
                            palette,
                            bits_per_pixel,
                        )
                    } else {
                        Ok(Pattern::Solid(0))
                    };
                    brush.and_then(|brush| {
                        let patblt = Fill {
                            dest: [order.left, order.top, order.width, order.height],
                            rop: order.rop,
                            brush,
                            clip,
                        };
                        fill(self.patblt, patblt, framebuffer, &mut budget, &mut painted)
                    })
                }
                DrawingOrder::OpaqueRect { order, clip } => {
                    order_color(order.color, palette, bits_per_pixel).and_then(|color| {
                        let opaque_rect = Fill {
                            dest: [order.left, order.top, order.width, order.height],
                            rop: PATCOPY,
                            brush: Pattern::Solid(color),
                            clip,
                        };
                        fill(
                            self.patblt,
                            opaque_rect,
                            framebuffer,
                            &mut budget,
                            &mut painted,
                        )
                    })
                }
                DrawingOrder::MultiOpaqueRect { order, clip } => {
                    order_color(order.color, palette, bits_per_pixel).and_then(|color| {
                        if !self.multi_opaque_rect {
                            tracing::warn!(
                                target: "rdp_orders",
                                "a drawing order this client did not advertise, painted anyway"
                            );
                        }
                        self.history
                            .multi_opaque_rect_rects()
                            .iter()
                            .try_for_each(|&dest| {
                                let rect = Fill {
                                    dest,
                                    rop: PATCOPY,
                                    brush: Pattern::Solid(color),
                                    clip,
                                };
                                fill(true, rect, framebuffer, &mut budget, &mut painted)
                            })
                    })
                }
                DrawingOrder::ScrBlt { order, clip } => {
                    self.scrblt(&order, clip, framebuffer, &mut budget, &mut painted)
                }
                DrawingOrder::MemBlt { order, clip } => self.blt(
                    self.memblt,
                    &order,
                    None,
                    clip,
                    framebuffer,
                    palette,
                    bits_per_pixel,
                    &mut budget,
                    &mut painted,
                ),
                DrawingOrder::Mem3Blt { order, clip } => self.blt(
                    self.mem3blt,
                    &order.blt,
                    Some(&order),
                    clip,
                    framebuffer,
                    palette,
                    bits_per_pixel,
                    &mut budget,
                    &mut painted,
                ),
                DrawingOrder::FrameMarker { action } => {
                    self.frame_marker(action, frames);
                    Ok(())
                }
                DrawingOrder::SkippedSecondary { order_type } => {
                    tracing::debug!(
                        target: "rdp_orders",
                        order_type,
                        "a secondary drawing order of a type not decoded, skipped"
                    );
                    Ok(())
                }
            };
            self.deliver(&mut painted, frames);
            match outcome {
                Ok(()) => {}
                Err(NotApplied::Skipped(Skip::OverBudget)) => over_budget += 1,
                Err(NotApplied::Skipped(reason)) => {
                    tracing::debug!(target: "rdp_orders", ?reason, "drawing order skipped");
                }
                Err(NotApplied::Failed(error)) => return Err(error),
            }
        }
        if over_budget > 0 {
            tracing::warn!(
                target: "rdp_paint_budget",
                update = "TS_UPDATE_ORDERS",
                declared = update.number_orders,
                skipped = over_budget,
                "paint budget reached; the remaining orders of this update were decoded, not painted",
            );
        }
        Ok(())
    }

    /// Store a Cache Glyph's glyphs. One outside the caches is skipped; one larger than its
    /// cache's cells is skipped and its entry emptied.
    fn cache_glyph(
        &mut self,
        order: &CacheGlyph<'_>,
        budget: &mut usize,
    ) -> Result<(), NotApplied> {
        let mut outcome = Ok(());
        for glyph in order.glyphs() {
            let Some((cache, cell)) = self.glyphs.get_mut(usize::from(order.cache_id)) else {
                outcome = Err(NotApplied::Skipped(Skip::UncachedGlyph));
                continue;
            };
            let Some(slot) = cache.get_mut(usize::from(glyph.cache_index)) else {
                outcome = Err(NotApplied::Skipped(Skip::UncachedGlyph));
                continue;
            };
            if glyph.bits.len() > *cell {
                *slot = None;
                outcome = Err(NotApplied::Skipped(Skip::UncachedGlyph));
                continue;
            }
            if !charge(budget, glyph.bits.len()) {
                *slot = None;
                outcome = Err(NotApplied::Skipped(Skip::OverBudget));
                continue;
            }
            *slot = Some(Glyph {
                x: glyph.x,
                y: glyph.y,
                cx: glyph.cx,
                cy: glyph.cy,
                bits: glyph.bits.to_vec(),
            });
        }
        outcome
    }

    /// Paint a GlyphIndex: its opaque rectangle, then its glyphs in the text colour, clipped to
    /// its text rectangle and its bounds.
    #[allow(clippy::too_many_arguments)]
    fn glyph_index(
        &self,
        order: &GlyphIndex,
        clip: Clip,
        framebuffer: &mut Framebuffer,
        palette: &Palette,
        bits_per_pixel: u16,
        budget: &mut usize,
        frames: &mut Vec<FrameUpdate>,
    ) -> Result<(), NotApplied> {
        if !self.glyph_index {
            tracing::warn!(
                target: "rdp_orders",
                "a GlyphIndex this client did not advertise, painted anyway"
            );
        }
        if matches!(clip, Clip::Unknown) {
            return Err(NotApplied::Skipped(Skip::UnknownClip));
        }
        let text = order_color(order.back_color, palette, bits_per_pixel)?;
        if order.op_redundant == 0
            && let Some(op) = inclusive(order.op)
        {
            let color = order_color(order.fore_color, palette, bits_per_pixel)?;
            let opaque = Fill {
                dest: op,
                rop: PATCOPY,
                brush: Pattern::Solid(color),
                clip,
            };
            fill(true, opaque, framebuffer, budget, frames)?;
        }
        let Some(bk) = inclusive(order.bk) else {
            return Ok(());
        };
        let clip = match clip {
            Clip::Bounds(bounds) => Some(bounds),
            _ => None,
        };
        let size = (framebuffer.width(), framebuffer.height());
        let Some(area) = clip_blt(bk, [bk[0], bk[1]], size, framebuffer, clip) else {
            return Ok(());
        };
        if !charge(budget, area.width * area.height * 4) {
            return Err(NotApplied::Skipped(Skip::OverBudget));
        }
        let stride = usize::from(framebuffer.width()) * 4;
        let mut block = Vec::with_capacity(area.width * area.height * 4);
        for row in 0..area.height {
            let start = (area.top as usize + row) * stride + area.left as usize * 4;
            block.extend_from_slice(&framebuffer.pixels()[start..start + area.width * 4]);
        }
        let text = text.to_le_bytes();
        let data = self.history.glyph_index_data();
        let (mut x, mut y) = (i32::from(order.x), i32::from(order.y));
        let deltas = order.char_inc == 0 && order.fl_accel & SO_CHAR_INC_EQUAL_BM_BASE == 0;
        let mut outcome = Ok(());
        let mut at = 0;
        while let Some(&index) = data.get(at) {
            at += 1;
            if index >= GLYPH_FRAGMENT_USE {
                outcome = Err(NotApplied::Skipped(Skip::GlyphFragment));
                break;
            }
            if deltas && let Some(&delta) = data.get(at) {
                at += 1;
                let mut delta = i32::from(delta);
                if delta & 0x80 != 0 && at + 1 < data.len() {
                    delta = i32::from(u16::from_le_bytes([data[at], data[at + 1]]));
                    at += 2;
                }
                if order.fl_accel & SO_VERTICAL != 0 {
                    y += delta;
                }
                if order.fl_accel & SO_HORIZONTAL != 0 {
                    x += delta;
                }
            }
            let glyph = self
                .glyphs
                .get(usize::from(order.cache_id))
                .and_then(|(cache, _)| cache.get(usize::from(index)))
                .and_then(Option::as_ref);
            let Some(glyph) = glyph else {
                outcome = Err(NotApplied::Skipped(Skip::CacheMiss));
                if order.fl_accel & SO_CHAR_INC_EQUAL_BM_BASE == 0 {
                    x += i32::from(order.char_inc);
                }
                continue;
            };
            let (left, top) = (x + i32::from(glyph.x), y + i32::from(glyph.y));
            let row_bytes = usize::from(glyph.cx).div_ceil(8);
            let rows = (area.top - top).max(0)
                ..(area.top + area.height as i32 - top).min(i32::from(glyph.cy));
            let columns = (area.left - left).max(0)
                ..(area.left + area.width as i32 - left).min(i32::from(glyph.cx));
            for row in rows {
                let py = top + row - area.top;
                for column in columns.clone() {
                    let px = left + column - area.left;
                    let byte = glyph.bits[row as usize * row_bytes + column as usize / 8];
                    if byte & (0x80 >> (column % 8)) != 0 {
                        let o = (py as usize * area.width + px as usize) * 4;
                        block[o..o + 4].copy_from_slice(&text);
                    }
                }
            }
            if order.fl_accel & SO_CHAR_INC_EQUAL_BM_BASE != 0 {
                x += i32::from(glyph.cx);
            } else if order.char_inc != 0 {
                x += i32::from(order.char_inc);
            }
        }
        frames.extend(area.blit(framebuffer, &block));
        outcome
    }

    /// Store a Cache Bitmap (Revision 2) bitmap. Past the budget the entry is emptied instead,
    /// so a later MemBlt naming it misses rather than painting what was there before.
    fn cache_bitmap(
        &mut self,
        order: &CacheBitmapRev2<'_>,
        palette: &Palette,
        bits_per_pixel: u16,
        budget: &mut usize,
    ) -> Result<(), NotApplied> {
        let tile = 16usize << order.cache_id;
        let slot = self.slot(u16::from(order.cache_id), order.cache_index)?;
        let (width, height) = (usize::from(order.width), usize::from(order.height));
        if width * height > tile * tile {
            *slot = None;
            return Err(NotApplied::Skipped(Skip::OversizedBitmap));
        }
        if !charge(budget, width * height * 4) {
            *slot = None;
            return Err(NotApplied::Skipped(Skip::OverBudget));
        }
        // The order names 16 bpp for a 15 bpp session too.
        let bpp = match (order.bits_per_pixel, bits_per_pixel) {
            (16, 15) => 15,
            (bpp, _) => bpp,
        };
        let rgba = decode_bitmap(order.compressed, bpp, order.data, width, height, palette)
            .map_err(NotApplied::Failed)?;
        *slot = Some(CachedBitmap {
            width: order.width,
            height: order.height,
            rgba,
        });
        Ok(())
    }

    /// The cache entry `(cache_id, index)` names: the waiting-list entry past the cache's
    /// last for [`BITMAPCACHE_WAITING_LIST_INDEX`].
    fn slot(&mut self, cache_id: u16, index: u16) -> Result<&mut Option<CachedBitmap>, NotApplied> {
        let cache = self
            .caches
            .get_mut(usize::from(cache_id))
            .ok_or(NotApplied::Skipped(Skip::CacheOutOfRange))?;
        let last = cache.len() - 1;
        let index = if index == BITMAPCACHE_WAITING_LIST_INDEX {
            last
        } else if usize::from(index) < last {
            usize::from(index)
        } else {
            return Err(NotApplied::Skipped(Skip::CacheOutOfRange));
        };
        Ok(&mut cache[index])
    }

    /// Paint a MemBlt, or a Mem3Blt when `mem3blt` carries its colours and brush.
    #[allow(clippy::too_many_arguments)]
    fn blt(
        &mut self,
        advertised: bool,
        order: &MemBlt,
        mem3blt: Option<&Mem3Blt>,
        clip: Clip,
        framebuffer: &mut Framebuffer,
        palette: &Palette,
        bits_per_pixel: u16,
        budget: &mut usize,
        frames: &mut Vec<FrameUpdate>,
    ) -> Result<(), NotApplied> {
        if !advertised {
            tracing::warn!(
                target: "rdp_orders",
                rop = order.rop,
                "a drawing order this client did not advertise, painted anyway"
            );
        }
        // The high byte names a colour table; the colours are the session palette's.
        if bits_per_pixel <= 8 && order.cache_id >> 8 != 0 {
            tracing::warn!(
                target: "rdp_orders",
                color_table = order.cache_id >> 8,
                "a blit names a colour table other than 0; its colours come from the palette"
            );
        }
        let clip = match clip {
            Clip::None => None,
            Clip::Bounds(bounds) => Some(bounds),
            Clip::Unknown => return Err(NotApplied::Skipped(Skip::UnknownClip)),
        };
        let pattern = match mem3blt {
            Some(order) if rop::uses_pattern(order.blt.rop) => Some(pattern(
                &order.brush,
                order.fore_color,
                order.back_color,
                palette,
                bits_per_pixel,
            )?),
            _ => None,
        };
        // The low byte is the cache.
        let cache_id = order.cache_id & 0x00FF;
        let bitmap = self
            .slot(cache_id, order.cache_index)?
            .as_ref()
            .ok_or(NotApplied::Skipped(Skip::CacheMiss))?;
        let Some(area) = clip_blt(
            [order.left, order.top, order.width, order.height],
            [order.x_src, order.y_src],
            (bitmap.width, bitmap.height),
            framebuffer,
            clip,
        ) else {
            return Ok(());
        };
        if !charge(budget, area.width * area.height * 4) {
            return Err(NotApplied::Skipped(Skip::OverBudget));
        }
        let block = compose(
            &area,
            &bitmap.rgba,
            usize::from(bitmap.width),
            order.rop,
            pattern,
            framebuffer,
        );
        frames.extend(area.blit(framebuffer, &block));
        Ok(())
    }

    /// Paint a ScrBlt: a copy within the framebuffer, read whole before anything is written.
    fn scrblt(
        &self,
        order: &ScrBlt,
        clip: Clip,
        framebuffer: &mut Framebuffer,
        budget: &mut usize,
        frames: &mut Vec<FrameUpdate>,
    ) -> Result<(), NotApplied> {
        if !self.scrblt {
            tracing::warn!(
                target: "rdp_orders",
                rop = order.rop,
                "a drawing order this client did not advertise, painted anyway"
            );
        }
        let clip = match clip {
            Clip::None => None,
            Clip::Bounds(bounds) => Some(bounds),
            Clip::Unknown => return Err(NotApplied::Skipped(Skip::UnknownClip)),
        };
        let Some(area) = clip_blt(
            [order.left, order.top, order.width, order.height],
            [order.x_src, order.y_src],
            (framebuffer.width(), framebuffer.height()),
            framebuffer,
            clip,
        ) else {
            return Ok(());
        };
        // The source copy and the destination block.
        if !charge(budget, area.width * area.height * 4 * 2) {
            return Err(NotApplied::Skipped(Skip::OverBudget));
        }
        let stride = usize::from(framebuffer.width()) * 4;
        let mut source = Vec::with_capacity(area.width * area.height * 4);
        for row in 0..area.height {
            let start = (area.top + area.shift_y) as usize * stride
                + row * stride
                + (area.left + area.shift_x) as usize * 4;
            source.extend_from_slice(&framebuffer.pixels()[start..start + area.width * 4]);
        }
        let copied = Area {
            shift_x: -area.left,
            shift_y: -area.top,
            ..area
        };
        let block = compose(&copied, &source, area.width, order.rop, None, framebuffer);
        frames.extend(area.blit(framebuffer, &block));
        Ok(())
    }
}

/// A blit's destination after clipping, and the offset from it to the source.
#[derive(Debug, Clone, Copy)]
struct Area {
    left: i32,
    top: i32,
    width: usize,
    height: usize,
    shift_x: i32,
    shift_y: i32,
}

impl Area {
    fn blit(&self, framebuffer: &mut Framebuffer, block: &[u8]) -> Option<FrameUpdate> {
        framebuffer.blit(
            self.left as u16,
            self.top as u16,
            self.width as u16,
            self.height as u16,
            block,
            self.width,
        )
    }
}

/// The part of `dest` (left, top, width, height) that lies on the framebuffer, inside the
/// inclusive `clip`, and over a source of `source` size read from `src`; `None` when empty.
fn clip_blt(
    dest: [i16; 4],
    src: [i16; 2],
    source: (u16, u16),
    framebuffer: &Framebuffer,
    clip: Option<Bounds>,
) -> Option<Area> {
    let [left, top, width, height] = dest.map(i32::from);
    let shift_x = i32::from(src[0]) - left;
    let shift_y = i32::from(src[1]) - top;
    let mut l = left.max(0).max(-shift_x);
    let mut t = top.max(0).max(-shift_y);
    let mut r = (left + width)
        .min(i32::from(framebuffer.width()))
        .min(i32::from(source.0) - shift_x);
    let mut b = (top + height)
        .min(i32::from(framebuffer.height()))
        .min(i32::from(source.1) - shift_y);
    if let Some(bounds) = clip {
        l = l.max(i32::from(bounds.left));
        t = t.max(i32::from(bounds.top));
        r = r.min(i32::from(bounds.right) + 1);
        b = b.min(i32::from(bounds.bottom) + 1);
    }
    (l < r && t < b).then(|| Area {
        left: l,
        top: t,
        width: (r - l) as usize,
        height: (b - t) as usize,
        shift_x,
        shift_y,
    })
}

/// A Cache Color Table, which does not paint: 8 bpp colours resolve through the session palette.
/// One that differs from the palette, or names an entry past the six, is logged.
fn color_table(order: &CacheColorTable<'_>, palette: &Palette) -> Result<(), NotApplied> {
    if order.cache_index > 5 {
        return Err(NotApplied::Skipped(Skip::OutsideColorTables));
    }
    let differing = order
        .colors()
        .zip(palette.entries)
        .filter(|(table, entry)| table != entry)
        .count();
    if differing > 0 {
        tracing::warn!(
            target: "rdp_orders",
            cache_index = order.cache_index,
            differing,
            "a colour table differs from the session palette; colours come from the palette"
        );
    }
    Ok(())
}

/// One cached glyph: its offset from the glyph origin, its size, and one bit per pixel in
/// whole-byte rows, most significant first.
#[derive(Debug, Clone)]
struct Glyph {
    x: i16,
    y: i16,
    cx: u16,
    cy: u16,
    bits: Vec<u8>,
}

/// `flAccel` `SO_HORIZONTAL`.
const SO_HORIZONTAL: u8 = 0x02;
/// `flAccel` `SO_VERTICAL`.
const SO_VERTICAL: u8 = 0x04;
/// `flAccel` `SO_CHAR_INC_EQUAL_BM_BASE`: each glyph advances by its width.
const SO_CHAR_INC_EQUAL_BM_BASE: u8 = 0x20;
/// The `VariableBytes` USE operation; ADD is 0xFF.
const GLYPH_FRAGMENT_USE: u8 = 0xFE;

/// An inclusive `[left, top, right, bottom]` as `[left, top, width, height]`, empty unless right
/// and bottom pass left and top, the width and height capped to the coordinate range.
fn inclusive([left, top, right, bottom]: [i16; 4]) -> Option<[i16; 4]> {
    let side = |low: i16, high: i16| {
        (high > low).then(|| (i32::from(high) - i32::from(low) + 1).min(i32::from(i16::MAX)) as i16)
    };
    Some([left, top, side(left, right)?, side(top, bottom)?])
}

/// A rectangle painted with a brush through a ROP over its own pixels: a DstBlt, a PatBlt or an
/// OpaqueRect.
struct Fill {
    /// `[left, top, width, height]`.
    dest: [i16; 4],
    rop: u8,
    brush: Pattern,
    clip: Clip,
}

/// Paint `order`, logging it when its order type was not `advertised`.
fn fill(
    advertised: bool,
    order: Fill,
    framebuffer: &mut Framebuffer,
    budget: &mut usize,
    frames: &mut Vec<FrameUpdate>,
) -> Result<(), NotApplied> {
    let Fill {
        dest,
        rop,
        brush,
        clip,
    } = order;
    if !advertised {
        tracing::warn!(
            target: "rdp_orders",
            rop,
            "a drawing order this client did not advertise, painted anyway"
        );
    }
    let clip = match clip {
        Clip::None => None,
        Clip::Bounds(bounds) => Some(bounds),
        Clip::Unknown => return Err(NotApplied::Skipped(Skip::UnknownClip)),
    };
    let size = (framebuffer.width(), framebuffer.height());
    let Some(area) = clip_blt(dest, [dest[0], dest[1]], size, framebuffer, clip) else {
        return Ok(());
    };
    if !charge(budget, area.width * area.height * 4) {
        return Err(NotApplied::Skipped(Skip::OverBudget));
    }
    let stride = usize::from(framebuffer.width()) * 4;
    let mut block = vec![0u8; area.width * area.height * 4];
    for row in 0..area.height {
        let y = area.top as usize + row;
        let start = y * stride + area.left as usize * 4;
        let target = &framebuffer.pixels()[start..start + area.width * 4];
        let out = &mut block[row * area.width * 4..(row + 1) * area.width * 4];
        for column in 0..area.width {
            let at = column * 4;
            let p = brush.pixel(area.left + column as i32, y as i32);
            let d = word(&target[at..at + 4]);
            out[at..at + 4].copy_from_slice(&rop::rop3(rop, p, 0, d).to_le_bytes());
        }
    }
    frames.extend(area.blit(framebuffer, &block));
    Ok(())
}

/// The pixels `area` receives: `source` (RGBA, `source_width` wide) through `rop`, with the
/// pattern and the framebuffer's current pixels as the other two inputs.
fn compose(
    area: &Area,
    source: &[u8],
    source_width: usize,
    rop: u8,
    pattern: Option<Pattern>,
    framebuffer: &Framebuffer,
) -> Vec<u8> {
    let (width, height) = (area.width, area.height);
    let source_stride = source_width * 4;
    let target_stride = usize::from(framebuffer.width()) * 4;
    let mut block = vec![0u8; width * height * 4];
    for row in 0..height {
        let y = area.top as usize + row;
        let source_start = (y as i32 + area.shift_y) as usize * source_stride
            + (area.left + area.shift_x) as usize * 4;
        let source = &source[source_start..source_start + width * 4];
        let out = &mut block[row * width * 4..(row + 1) * width * 4];
        if rop == SRCCOPY {
            out.copy_from_slice(source);
            continue;
        }
        let target_start = y * target_stride + area.left as usize * 4;
        let target = &framebuffer.pixels()[target_start..target_start + width * 4];
        for column in 0..width {
            let at = column * 4;
            let p = pattern.map_or(0, |p| p.pixel(area.left + column as i32, y as i32));
            let s = word(&source[at..at + 4]);
            let d = word(&target[at..at + 4]);
            out[at..at + 4].copy_from_slice(&rop::rop3(rop, p, s, d).to_le_bytes());
        }
    }
    block
}

/// Why an order was not applied: skipped, or failed on malformed data.
enum NotApplied {
    Skipped(Skip),
    Failed(crate::SessionError),
}

fn word(pixel: &[u8]) -> u32 {
    u32::from_le_bytes([pixel[0], pixel[1], pixel[2], pixel[3]])
}

/// A brush with its `ForeColor` and `BackColor`, ready to paint.
fn pattern(
    brush: &Brush,
    fore_color: u32,
    back_color: u32,
    palette: &Palette,
    bits_per_pixel: u16,
) -> Result<Pattern, NotApplied> {
    let fore = order_color(fore_color, palette, bits_per_pixel)?;
    let back = order_color(back_color, palette, bits_per_pixel)?;
    let rows = match brush.style {
        rop::BS_SOLID => return Ok(Pattern::Solid(fore)),
        rop::BS_HATCHED => *rop::HATCH_PATTERNS
            .get(usize::from(brush.hatch))
            .ok_or(NotApplied::Skipped(Skip::UnsupportedBrush))?,
        rop::BS_PATTERN => rop::pattern_rows(brush.hatch, &brush.extra),
        _ => return Err(NotApplied::Skipped(Skip::UnsupportedBrush)),
    };
    Ok(Pattern::Mono {
        rows,
        fore,
        back,
        org_x: brush.org_x,
        org_y: brush.org_y,
    })
}

/// A TS_COLOR as an RGBA8888 word. Below 15 bpp the first byte is a palette index; at 15 and
/// 16 bpp the first two bytes are the pixel, as FreeRDP's `gdi_decode_color` reads them; above,
/// the bytes are red, green, blue.
fn order_color(value: u32, palette: &Palette, bits_per_pixel: u16) -> Result<u32, NotApplied> {
    let bytes = value.to_le_bytes();
    let rgba = match bits_per_pixel {
        8 => color::to_rgba(&bytes[..1], 1, 1, 8, palette, false),
        15 | 16 => color::to_rgba(&bytes[..2], 1, 1, bits_per_pixel, palette, false),
        _ => return Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0xFF])),
    }
    .map_err(|error| NotApplied::Failed(crate::SessionError::Color(error)))?;
    Ok(word(&rgba))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use justrdp_pdu::capability::{
        BitmapCacheCellInfo, BitmapCacheRev2CapabilitySet, OrderCapabilitySet,
    };
    use justrdp_pdu::orders::{
        TS_BOUNDS, TS_CACHE_BITMAP_UNCOMPRESSED_REV2, TS_ENC_MEM3BLT_ORDER, TS_ENC_MEMBLT_ORDER,
        TS_SECONDARY, TS_STANDARD, TS_TYPE_CHANGE,
    };

    pub(crate) const RED: u16 = 0xF800;
    pub(crate) const GREEN: u16 = 0x07E0;
    pub(crate) const BLUE: u16 = 0x001F;
    pub(crate) const WHITE: u16 = 0xFFFF;

    pub(crate) fn rgba(pixel: u16) -> [u8; 4] {
        let rgba =
            color::to_rgba(&pixel.to_le_bytes(), 1, 1, 16, &Palette::default(), false).unwrap();
        [rgba[0], rgba[1], rgba[2], rgba[3]]
    }

    /// The capability sets with DstBlt, PatBlt, ScrBlt, MemBlt (and Mem3Blt) over three
    /// Revision 2 caches of `entries`.
    pub(crate) fn capabilities(entries: u32, mem3blt: bool) -> Vec<CapabilitySet> {
        let mut order = OrderCapabilitySet::default();
        order.order_support[capability::ORDER_NEG_DSTBLT_INDEX] = 1;
        order.order_support[capability::ORDER_NEG_PATBLT_INDEX] = 1;
        order.order_support[capability::ORDER_NEG_SCRBLT_INDEX] = 1;
        order.order_support[capability::ORDER_NEG_MEMBLT_INDEX] = 1;
        order.order_support[capability::ORDER_NEG_MEM3BLT_INDEX] = u8::from(mem3blt);
        vec![
            CapabilitySet::Order(order),
            CapabilitySet::BitmapCacheRev2(BitmapCacheRev2CapabilitySet {
                cache_flags: 0,
                cells: vec![
                    BitmapCacheCellInfo {
                        entries,
                        persistent: false,
                    };
                    3
                ],
            }),
        ]
    }

    /// A Cache Bitmap (Revision 2) order storing an uncompressed 16-bpp bitmap, `rows` top-down.
    pub(crate) fn cache_bitmap(cache_id: u16, index: u16, rows: &[&[u16]]) -> Vec<u8> {
        let (width, height) = (rows[0].len(), rows.len());
        let mut data = Vec::new();
        for row in rows.iter().rev() {
            for pixel in *row {
                data.extend_from_slice(&pixel.to_le_bytes());
            }
        }
        let length = data.len();
        let mut body = vec![0x80 | (width >> 8) as u8, width as u8];
        body.extend_from_slice(&[0x80 | (height >> 8) as u8, height as u8]);
        body.extend_from_slice(&[
            0xC0 | (length >> 24) as u8,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
        ]);
        body.extend_from_slice(&[0x80 | (index >> 8) as u8, index as u8]);
        body.extend_from_slice(&data);
        let mut order = vec![TS_STANDARD | TS_SECONDARY];
        order.extend_from_slice(&((body.len() as i16) - 7).to_le_bytes());
        order.extend_from_slice(&(cache_id | 0x4 << 3).to_le_bytes());
        order.push(TS_CACHE_BITMAP_UNCOMPRESSED_REV2);
        order.extend_from_slice(&body);
        order
    }

    /// A MemBlt with every field and absolute coordinates.
    pub(crate) fn memblt(cache: (u16, u16), dest: [i16; 4], rop: u8, src: [i16; 2]) -> Vec<u8> {
        let mut order = vec![
            TS_STANDARD | TS_TYPE_CHANGE,
            TS_ENC_MEMBLT_ORDER,
            0xFF,
            0x01,
        ];
        order.extend_from_slice(&cache.0.to_le_bytes());
        for value in dest {
            order.extend_from_slice(&value.to_le_bytes());
        }
        order.push(rop);
        for value in src {
            order.extend_from_slice(&value.to_le_bytes());
        }
        order.extend_from_slice(&cache.1.to_le_bytes());
        order
    }

    /// A Mem3Blt with every field: `brush` is `BrushOrgX`, `BrushOrgY`, `BrushStyle`,
    /// `BrushHatch`, and `colors` are `BackColor`, `ForeColor`.
    fn mem3blt(
        cache: (u16, u16),
        dest: [i16; 4],
        rop: u8,
        colors: [u16; 2],
        brush: [u8; 4],
    ) -> Vec<u8> {
        let mut order = vec![
            TS_STANDARD | TS_TYPE_CHANGE,
            TS_ENC_MEM3BLT_ORDER,
            0xFF,
            0xFF,
            0x00,
        ];
        order.extend_from_slice(&cache.0.to_le_bytes());
        for value in dest {
            order.extend_from_slice(&value.to_le_bytes());
        }
        order.push(rop);
        order.extend_from_slice(&[0; 4]); // nXSrc, nYSrc
        for color in colors {
            order.extend_from_slice(&color.to_le_bytes());
            order.push(0);
        }
        order.extend_from_slice(&brush);
        order.extend_from_slice(&[0; 7]);
        order.extend_from_slice(&cache.1.to_le_bytes());
        order
    }

    /// A PatBlt with every field: `colors` are `BackColor`, `ForeColor`, and `brush` is
    /// `BrushOrgX`, `BrushOrgY`, `BrushStyle`, `BrushHatch`.
    pub(crate) fn patblt(dest: [i16; 4], rop: u8, colors: [u16; 2], brush: [u8; 4]) -> Vec<u8> {
        let mut order = vec![
            TS_STANDARD | TS_TYPE_CHANGE,
            justrdp_pdu::orders::TS_ENC_PATBLT_ORDER,
            0xFF,
            0x0F,
        ];
        for value in dest {
            order.extend_from_slice(&value.to_le_bytes());
        }
        order.push(rop);
        for color in colors {
            order.extend_from_slice(&color.to_le_bytes());
            order.push(0);
        }
        order.extend_from_slice(&brush);
        order.extend_from_slice(&[0; 7]);
        order
    }

    /// An OpaqueRect of a 16 bpp `color`, whose two bytes are `RedOrPaletteIndex` and `Green`.
    pub(crate) fn opaque_rect(dest: [i16; 4], color: u16) -> Vec<u8> {
        let mut order = vec![
            TS_STANDARD | TS_TYPE_CHANGE,
            justrdp_pdu::orders::TS_ENC_OPAQUERECT_ORDER,
            0x7F,
        ];
        for value in dest {
            order.extend_from_slice(&value.to_le_bytes());
        }
        order.extend_from_slice(&color.to_le_bytes());
        order.push(0);
        order
    }

    /// OpaqueRect fills its rectangle with its colour, clipped to the framebuffer; PatBlt
    /// paints its brush through its ROP over what is there (#475).
    #[test]
    fn opaque_rect_and_patblt_fill_their_rectangles() {
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(4, 2).unwrap();
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                opaque_rect([1, 0, 2, 1], RED),
                opaque_rect([3, 1, 5, 5], GREEN),
            ],
        );
        assert_eq!(frames, [frame(1, 0, 2, 1), frame(3, 1, 1, 1)]);
        assert_eq!(pixel(&fb, 0, 0), BLACK);
        assert_eq!(pixel(&fb, 1, 0), rgba(RED));
        assert_eq!(pixel(&fb, 2, 0), rgba(RED));
        assert_eq!(pixel(&fb, 3, 1), rgba(GREEN));

        let frames = run(
            &mut orders,
            &mut fb,
            &[
                // PATCOPY, solid: the foreground.
                patblt([0, 1, 1, 1], 0xF0, [WHITE, BLUE], [0, 0, rop::BS_SOLID, 0]),
                // PATINVERT over the red: pattern XOR destination.
                patblt([1, 0, 1, 1], 0x5A, [WHITE, BLUE], [0, 0, rop::BS_SOLID, 0]),
                // DSTINVERT reads no pattern.
                patblt([2, 0, 1, 1], 0x55, [WHITE, BLUE], [0, 0, rop::BS_SOLID, 0]),
                // PATCOPY, HS_HORIZONTAL from origin (0, -3): row 3 of the pattern, the
                // line, lands on row 0 and paints the foreground; row 1 is background.
                patblt(
                    [3, 0, 1, 2],
                    0xF0,
                    [WHITE, BLUE],
                    [0, (-3i8) as u8, rop::BS_HATCHED, 0],
                ),
            ],
        );
        assert_eq!(frames.len(), 4);
        assert_eq!(pixel(&fb, 0, 1), rgba(BLUE));
        let word = |p: [u8; 4]| u32::from_le_bytes(p);
        assert_eq!(
            word(pixel(&fb, 1, 0)),
            rop::rop3(0x5A, word(rgba(BLUE)), 0, word(rgba(RED)))
        );
        assert_eq!(
            word(pixel(&fb, 2, 0)),
            rop::rop3(0x55, 0, 0, word(rgba(RED)))
        );
        assert_ne!(pixel(&fb, 2, 0), rgba(RED), "DSTINVERT changed it");
        assert_eq!(pixel(&fb, 3, 0), rgba(BLUE));
        assert_eq!(pixel(&fb, 3, 1), rgba(WHITE));
    }

    /// A MultiOpaqueRect of a 16 bpp `color` over `rects` (`[left, top, width, height]`), each
    /// component a one-byte delta, inside the inclusive `bounds` when there are some.
    pub(crate) fn multi_opaque_rect(
        bounds: Option<[i16; 4]>,
        color: u16,
        rects: &[[i16; 4]],
    ) -> Vec<u8> {
        let control = TS_STANDARD | TS_TYPE_CHANGE | if bounds.is_some() { TS_BOUNDS } else { 0 };
        let mut order = vec![
            control,
            justrdp_pdu::orders::TS_ENC_MULTIOPAQUERECT_ORDER,
            0xB0,
            0x01,
        ];
        if let Some(edges) = bounds {
            order.push(0x0F);
            for edge in edges {
                order.extend_from_slice(&edge.to_le_bytes());
            }
        }
        order.extend_from_slice(&color.to_le_bytes());
        order.push(rects.len() as u8);
        let mut list = vec![0u8; rects.len().div_ceil(2)];
        let mut previous = [0i16; 2];
        for rect in rects {
            for value in [
                rect[0] - previous[0],
                rect[1] - previous[1],
                rect[2],
                rect[3],
            ] {
                assert!((-64..64).contains(&value), "a one-byte delta");
                list.push((value as i8 as u8) & 0x7F);
            }
            previous = [rect[0], rect[1]];
        }
        order.extend_from_slice(&(list.len() as u16).to_le_bytes());
        order.extend_from_slice(&list);
        order
    }

    /// MultiOpaqueRect fills each of its rectangles with its colour, a frame each, and paints
    /// nothing for an empty one; the bounds clip every rectangle (#485).
    #[test]
    fn multi_opaque_rect_fills_each_rectangle() {
        let mut sets = capabilities(4, true);
        if let CapabilitySet::Order(o) = &mut sets[0] {
            o.order_support[capability::ORDER_NEG_MULTIOPAQUERECT_INDEX] = 1;
        }
        let mut orders = Orders::new(&sets);
        let mut fb = Framebuffer::new(6, 3).unwrap();
        let frames = run(
            &mut orders,
            &mut fb,
            &[multi_opaque_rect(
                None,
                RED,
                &[[0, 0, 2, 1], [4, 1, 2, 1], [1, 2, 0, 1]],
            )],
        );
        assert_eq!(frames, [frame(0, 0, 2, 1), frame(4, 1, 2, 1)]);
        for (x, y) in [(0, 0), (1, 0), (4, 1), (5, 1)] {
            assert_eq!(pixel(&fb, x, y), rgba(RED), "({x}, {y})");
        }
        for (x, y) in [(2, 0), (3, 1), (1, 2)] {
            assert_eq!(pixel(&fb, x, y), BLACK, "({x}, {y})");
        }

        // Bounds of columns 0..=4, rows 0..=1: the first rectangle lies below them, the second
        // keeps its first column.
        let frames = run(
            &mut orders,
            &mut fb,
            &[multi_opaque_rect(
                Some([0, 0, 4, 1]),
                GREEN,
                &[[0, 2, 6, 1], [4, 1, 2, 1]],
            )],
        );
        assert_eq!(frames, [frame(4, 1, 1, 1)]);
        assert_eq!(pixel(&fb, 4, 1), rgba(GREEN));
        assert_eq!(pixel(&fb, 5, 1), rgba(RED));
        assert_eq!(pixel(&fb, 0, 2), BLACK);
    }

    /// A DstBlt with every field.
    pub(crate) fn dstblt(dest: [i16; 4], rop: u8) -> Vec<u8> {
        let mut order = vec![
            TS_STANDARD | TS_TYPE_CHANGE,
            justrdp_pdu::orders::TS_ENC_DSTBLT_ORDER,
            0x1F,
        ];
        for value in dest {
            order.extend_from_slice(&value.to_le_bytes());
        }
        order.push(rop);
        order
    }

    /// DstBlt runs its ROP on the destination alone (#475): BLACKNESS, DSTINVERT, WHITENESS. A
    /// ROP that reads the pattern or the source breaks 2.2.2.2.1.1.2.1's MUST and paints nothing.
    #[test]
    fn dstblt_runs_destination_only_rops_and_skips_the_rest() {
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(4, 1).unwrap();
        run(&mut orders, &mut fb, &[opaque_rect([0, 0, 4, 1], RED)]);
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                dstblt([0, 0, 1, 1], 0x00),
                dstblt([1, 0, 1, 1], 0x55),
                dstblt([2, 0, 1, 1], 0xFF),
                dstblt([3, 0, 1, 1], 0xF0),
            ],
        );
        assert_eq!(
            frames,
            [frame(0, 0, 1, 1), frame(1, 0, 1, 1), frame(2, 0, 1, 1)]
        );
        let word = |p: [u8; 4]| u32::from_le_bytes(p);
        assert_eq!(pixel(&fb, 0, 0), BLACK);
        assert_eq!(
            word(pixel(&fb, 1, 0)),
            rop::rop3(0x55, 0, 0, word(rgba(RED)))
        );
        assert_eq!(pixel(&fb, 2, 0), [0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(pixel(&fb, 3, 0), rgba(RED), "PATCOPY is not a DstBlt ROP");
    }

    /// [`capabilities`] with ten glyph caches of 4 entries and 16-byte cells, and GlyphIndex.
    fn glyph_capabilities() -> Vec<CapabilitySet> {
        let mut sets = capabilities(4, true);
        if let CapabilitySet::Order(o) = &mut sets[0] {
            o.order_support[capability::ORDER_NEG_INDEX_INDEX] = 1;
        }
        sets.push(CapabilitySet::GlyphCache(
            justrdp_pdu::capability::GlyphCacheCapabilitySet {
                glyph_cache: [(4, 16); 10],
                frag_cache: 0,
                glyph_support_level: capability::GLYPH_SUPPORT_FULL,
            },
        ));
        sets
    }

    /// A Cache Glyph order of one glyph: `rows` of `#` and `.`, its offset `(x, y)`.
    fn cache_glyph(cache_id: u8, index: u16, (x, y): (i16, i16), rows: &[&str]) -> Vec<u8> {
        let (cx, cy) = (rows[0].len(), rows.len());
        let mut body = vec![cache_id, 1];
        for value in [index, x as u16, y as u16, cx as u16, cy as u16] {
            body.extend_from_slice(&value.to_le_bytes());
        }
        let mut bits = Vec::new();
        for row in rows {
            let mut bytes = vec![0u8; cx.div_ceil(8)];
            for (column, c) in row.chars().enumerate() {
                if c == '#' {
                    bytes[column / 8] |= 0x80 >> (column % 8);
                }
            }
            bits.extend(bytes);
        }
        bits.resize(bits.len().next_multiple_of(4), 0);
        body.extend(bits);
        let mut order = vec![TS_STANDARD | TS_SECONDARY];
        order.extend_from_slice(&((body.len() as i16) - 7).to_le_bytes());
        order.extend_from_slice(&0u16.to_le_bytes());
        order.push(justrdp_pdu::orders::TS_CACHE_GLYPH);
        order.extend(body);
        order
    }

    /// A GlyphIndex with every field: `accel` is `cacheId`, `flAccel`, `ulCharInc`,
    /// `fOpRedundant`; `colors` are `BackColor` (the text), `ForeColor` (the opaque rectangle).
    fn glyph_index(
        accel: [u8; 4],
        colors: [u16; 2],
        bk: [i16; 4],
        op: [i16; 4],
        origin: (i16, i16),
        data: &[u8],
    ) -> Vec<u8> {
        let mut order = vec![
            TS_STANDARD | TS_TYPE_CHANGE,
            justrdp_pdu::orders::TS_ENC_INDEX_ORDER,
            0xFF,
            0xFF,
            0x3F,
        ];
        order.extend_from_slice(&accel);
        for color in colors {
            order.extend_from_slice(&color.to_le_bytes());
            order.push(0);
        }
        for value in bk.into_iter().chain(op) {
            order.extend_from_slice(&value.to_le_bytes());
        }
        order.extend_from_slice(&[0; 11]);
        order.extend_from_slice(&origin.0.to_le_bytes());
        order.extend_from_slice(&origin.1.to_le_bytes());
        order.push(data.len() as u8);
        order.extend_from_slice(data);
        order
    }

    /// The columns of row `y` that are `color`, as `#` and `.`.
    fn row_of(fb: &Framebuffer, y: usize, color: u16) -> String {
        (0..usize::from(fb.width()))
            .map(|x| {
                if pixel(fb, x, y) == rgba(color) {
                    '#'
                } else {
                    '.'
                }
            })
            .collect()
    }

    /// A glyph's set bits paint in `BackColor` at the origin plus its offset, and nothing else
    /// does; each delta, one byte or 0x80 and two, moves the origin before its glyph (#476, as
    /// FreeRDP's `update_glyph_offset`).
    #[test]
    fn glyphs_paint_their_set_bits_at_their_offsets() {
        let mut orders = Orders::new(&glyph_capabilities());
        let mut fb = Framebuffer::new(12, 3).unwrap();
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                opaque_rect([0, 0, 12, 3], WHITE),
                cache_glyph(2, 1, (0, -2), &["#.#", ".#."]),
                glyph_index(
                    [2, 0x03, 0, 1],
                    [BLUE, RED],
                    [0, 0, 11, 2],
                    [0; 4],
                    (2, 3),
                    &[1, 0, 1, 0x80, 5, 0],
                ),
            ],
        );
        assert_eq!(frames, [frame(0, 0, 12, 3), frame(0, 0, 12, 3)]);
        assert_eq!(row_of(&fb, 0, BLUE), "............");
        assert_eq!(row_of(&fb, 1, BLUE), "..#.#..#.#..");
        assert_eq!(row_of(&fb, 2, BLUE), "...#....#...");
        assert_eq!(
            row_of(&fb, 1, WHITE),
            "##.#.##.#.##",
            "clear bits are see-through"
        );
    }

    /// `SO_CHAR_INC_EQUAL_BM_BASE` advances each glyph by its width and `ulCharInc` by a fixed
    /// pitch, both with no delta bytes; the text rectangle clips.
    #[test]
    fn glyph_advances_and_the_text_rectangle() {
        let paint = |accel: [u8; 4], bk: [i16; 4]| {
            let mut orders = Orders::new(&glyph_capabilities());
            let mut fb = Framebuffer::new(12, 2).unwrap();
            run(
                &mut orders,
                &mut fb,
                &[
                    cache_glyph(0, 0, (0, 0), &["##"]),
                    glyph_index(accel, [BLUE, RED], bk, [0; 4], (1, 0), &[0, 0, 0]),
                ],
            );
            row_of(&fb, 0, BLUE)
        };
        assert_eq!(
            paint([0, 0x23, 0, 1], [0, 0, 11, 1]),
            ".######.....",
            "by width"
        );
        assert_eq!(
            paint([0, 0x03, 4, 1], [0, 0, 11, 1]),
            ".##..##..##.",
            "fixed pitch"
        );
        assert_eq!(
            paint([0, 0x23, 0, 1], [2, 0, 5, 1]),
            "..####......",
            "clipped"
        );
        assert_eq!(
            paint([0, 0x23, 0, 1], [0, 0, 11, 0]),
            "............",
            "a text rectangle whose bottom is its top is empty, as FreeRDP measures it"
        );
    }

    /// At a fixed pitch a missing glyph still takes its cell, so the glyphs after it keep their
    /// places.
    #[test]
    fn a_missing_glyph_keeps_its_cell_at_a_fixed_pitch() {
        let mut orders = Orders::new(&glyph_capabilities());
        let mut fb = Framebuffer::new(12, 2).unwrap();
        run(
            &mut orders,
            &mut fb,
            &[
                cache_glyph(0, 0, (0, 0), &["##"]),
                glyph_index(
                    [0, 0x03, 4, 1],
                    [BLUE, RED],
                    [0, 0, 11, 1],
                    [0; 4],
                    (1, 0),
                    &[3, 0],
                ),
            ],
        );
        assert_eq!(row_of(&fb, 0, BLUE), ".....##.....");
    }

    /// Unless `fOpRedundant`, the opaque rectangle fills in `ForeColor` before the glyphs.
    #[test]
    fn the_opaque_rectangle_fills_before_the_glyphs() {
        let mut orders = Orders::new(&glyph_capabilities());
        let mut fb = Framebuffer::new(6, 2).unwrap();
        run(
            &mut orders,
            &mut fb,
            &[
                cache_glyph(0, 0, (0, 0), &["#"]),
                glyph_index(
                    [0, 0x23, 0, 0],
                    [BLUE, RED],
                    [0, 0, 5, 1],
                    [1, 0, 4, 1],
                    (2, 0),
                    &[0],
                ),
            ],
        );
        assert_eq!(row_of(&fb, 0, RED), ".#.##.");
        assert_eq!(row_of(&fb, 0, BLUE), "..#...");
        let mut orders = Orders::new(&glyph_capabilities());
        let mut fb = Framebuffer::new(6, 2).unwrap();
        run(
            &mut orders,
            &mut fb,
            &[
                cache_glyph(0, 0, (0, 0), &["#"]),
                glyph_index(
                    [0, 0x23, 0, 1],
                    [BLUE, RED],
                    [0, 0, 5, 1],
                    [1, 0, 4, 1],
                    (2, 0),
                    &[0],
                ),
            ],
        );
        assert_eq!(row_of(&fb, 0, RED), "......", "redundant: no fill");
    }

    /// A fragment operation ends the run, since no fragment cache is kept; a glyph outside the
    /// caches or past its cell is not stored, and a miss draws nothing; the update goes on.
    #[test]
    fn fragments_and_uncached_glyphs_draw_nothing() {
        let mut orders = Orders::new(&glyph_capabilities());
        let mut fb = Framebuffer::new(8, 2).unwrap();
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                cache_glyph(0, 0, (0, 0), &["#"]),
                cache_glyph(0, 4, (0, 0), &["#"]),
                cache_glyph(10, 0, (0, 0), &["#"]),
                cache_glyph(1, 0, (0, 0), &["#"; 20]),
                glyph_index(
                    [0, 0x23, 0, 1],
                    [BLUE, RED],
                    [0, 0, 7, 1],
                    [0; 4],
                    (0, 0),
                    &[0, 0xFE, 0, 0],
                ),
                glyph_index(
                    [0, 0x23, 0, 1],
                    [BLUE, RED],
                    [0, 0, 7, 1],
                    [0; 4],
                    (3, 0),
                    &[4],
                ),
                glyph_index(
                    [1, 0x23, 0, 1],
                    [BLUE, RED],
                    [0, 0, 7, 1],
                    [0; 4],
                    (5, 0),
                    &[0],
                ),
                opaque_rect([7, 0, 1, 1], GREEN),
            ],
        );
        assert_eq!(row_of(&fb, 0, BLUE), "#.......");
        assert_eq!(pixel(&fb, 7, 0), rgba(GREEN));
        assert_eq!(frames.last(), Some(&frame(7, 0, 1, 1)));
    }

    /// A GlyphIndex with no text rectangle draws nothing, and the orders after it in the update
    /// are applied.
    #[test]
    fn a_glyph_index_with_no_text_rectangle_draws_nothing() {
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(4, 1).unwrap();
        let mut glyph_index = vec![
            TS_STANDARD | TS_TYPE_CHANGE,
            justrdp_pdu::orders::TS_ENC_INDEX_ORDER,
            0x00,
            0x00,
            0x20,
        ];
        glyph_index.extend_from_slice(&[2, 0x00, 0x01]); // VariableBytes: one glyph index
        let frames = run(
            &mut orders,
            &mut fb,
            &[glyph_index, opaque_rect([2, 0, 1, 1], RED)],
        );
        assert_eq!(frames, [frame(2, 0, 1, 1)]);
        assert_eq!(pixel(&fb, 2, 0), rgba(RED));
    }

    /// A PatBlt whose brush cannot be drawn paints nothing, and the update goes on, unless its
    /// ROP never reads the brush; one that was not advertised is painted all the same (ADR-0009
    /// §2: accept-and-log).
    #[test]
    fn patblt_with_a_cached_brush_is_skipped_and_unadvertised_ones_paint() {
        let mut fb = Framebuffer::new(2, 1).unwrap();
        let mut orders = Orders::new(&capabilities(4, true));
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                patblt(
                    [0, 0, 1, 1],
                    0xF0,
                    [WHITE, BLUE],
                    [0, 0, rop::TS_CACHED_BRUSH | 1, 0],
                ),
                opaque_rect([1, 0, 1, 1], RED),
            ],
        );
        assert_eq!(frames, [frame(1, 0, 1, 1)]);
        assert_eq!(pixel(&fb, 0, 0), BLACK);
        let frames = run(
            &mut orders,
            &mut fb,
            &[patblt(
                [1, 0, 1, 1],
                0x55,
                [WHITE, BLUE],
                [0, 0, rop::TS_CACHED_BRUSH | 1, 0],
            )],
        );
        assert_eq!(frames, [frame(1, 0, 1, 1)], "DSTINVERT reads no brush");
        assert_ne!(pixel(&fb, 1, 0), rgba(RED));
        let mut unadvertised = capabilities(4, true);
        if let CapabilitySet::Order(o) = &mut unadvertised[0] {
            o.order_support[capability::ORDER_NEG_PATBLT_INDEX] = 0;
        }
        let mut orders = Orders::new(&unadvertised);
        let frames = run(&mut orders, &mut fb, &[opaque_rect([0, 0, 1, 1], GREEN)]);
        assert_eq!(frames, [frame(0, 0, 1, 1)]);
        assert_eq!(pixel(&fb, 0, 0), rgba(GREEN));
    }

    fn run_with(
        orders: &mut Orders,
        fb: &mut Framebuffer,
        parts: &[Vec<u8>],
        budget: usize,
    ) -> Vec<FrameUpdate> {
        let data = parts.concat();
        let mut frames = Vec::new();
        orders
            .apply(
                OrdersUpdate {
                    number_orders: parts.len() as u16,
                    order_data: &data,
                },
                fb,
                &Palette::default(),
                16,
                budget,
                &mut frames,
            )
            .unwrap();
        frames
    }

    /// Apply `parts` in an 8 bpp session with `palette`.
    fn run_8bpp(
        orders: &mut Orders,
        fb: &mut Framebuffer,
        parts: &[Vec<u8>],
        palette: &Palette,
    ) -> Vec<FrameUpdate> {
        let data = parts.concat();
        let mut frames = Vec::new();
        orders
            .apply(
                OrdersUpdate {
                    number_orders: parts.len() as u16,
                    order_data: &data,
                },
                fb,
                palette,
                8,
                1 << 20,
                &mut frames,
            )
            .unwrap();
        frames
    }

    /// A Cache Bitmap (Revision 2) order storing an uncompressed 8 bpp bitmap of palette
    /// indices, `rows` top-down, four pixels wide so no row needs padding.
    fn cache_bitmap_8(cache_id: u16, index: u16, rows: &[[u8; 4]]) -> Vec<u8> {
        let data: Vec<u8> = rows.iter().rev().flatten().copied().collect();
        let mut body = vec![0x80, 4, 0x80, rows.len() as u8];
        body.extend_from_slice(&[0xC0, 0, 0, data.len() as u8]);
        body.extend_from_slice(&[0x80 | (index >> 8) as u8, index as u8]);
        body.extend(data);
        let mut order = vec![TS_STANDARD | TS_SECONDARY];
        order.extend_from_slice(&((body.len() as i16) - 7).to_le_bytes());
        order.extend_from_slice(&(cache_id | 0x3 << 3).to_le_bytes());
        order.push(TS_CACHE_BITMAP_UNCOMPRESSED_REV2);
        order.extend(body);
        order
    }

    /// A Cache Color Table of entry `index`, every colour `[r, g, b]` from `colors`.
    fn color_table(index: u8, colors: &[[u8; 3]; 256]) -> Vec<u8> {
        let mut body = vec![index];
        body.extend_from_slice(&256u16.to_le_bytes());
        for [r, g, b] in colors {
            body.extend_from_slice(&[*b, *g, *r, 0]);
        }
        let mut order = vec![TS_STANDARD | TS_SECONDARY];
        order.extend_from_slice(&((body.len() as i16) - 7).to_le_bytes());
        order.extend_from_slice(&0u16.to_le_bytes());
        order.push(justrdp_pdu::orders::TS_CACHE_COLOR_TABLE);
        order.extend(body);
        order
    }

    /// A palette whose entry 1 is red and 2 green.
    fn two_colour_palette() -> Palette {
        let mut palette = Palette::default();
        palette.entries[1] = [0xFF, 0, 0];
        palette.entries[2] = [0, 0xFF, 0];
        palette
    }

    /// At 8 bpp a cached bitmap's indices and an order's colour index resolve through the
    /// session palette (#477, as FreeRDP's `gdi_palette_update` palette).
    #[test]
    fn eight_bpp_orders_resolve_through_the_palette() {
        let palette = two_colour_palette();
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(4, 2).unwrap();
        run_8bpp(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap_8(0, 0, &[[1, 2, 1, 2]]),
                memblt((0, 0), [0, 0, 4, 1], SRCCOPY, [0, 0]),
                opaque_rect([0, 1, 4, 1], 2),
            ],
            &palette,
        );
        let red = [0xFF, 0, 0, 0xFF];
        let green = [0, 0xFF, 0, 0xFF];
        assert_eq!(
            [
                pixel(&fb, 0, 0),
                pixel(&fb, 1, 0),
                pixel(&fb, 2, 0),
                pixel(&fb, 3, 0)
            ],
            [red, green, red, green]
        );
        assert_eq!(pixel(&fb, 0, 1), green);
    }

    /// A Cache Color Table paints nothing; one that differs from the palette is logged, one
    /// equal to it is not, and an entry past the six is skipped (#477).
    #[test]
    #[tracing_test::traced_test]
    fn a_colour_table_unlike_the_palette_is_logged() {
        let palette = two_colour_palette();
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(4, 1).unwrap();
        let frames = run_8bpp(
            &mut orders,
            &mut fb,
            &[color_table(0, &palette.entries)],
            &palette,
        );
        assert_eq!(frames, []);
        assert!(!logs_contain("differs from the session palette"));
        let mut other = palette.entries;
        other[7] = [1, 2, 3];
        run_8bpp(&mut orders, &mut fb, &[color_table(1, &other)], &palette);
        assert!(logs_contain("differs from the session palette"));
        assert!(logs_contain("differing=1"));
        run_8bpp(&mut orders, &mut fb, &[color_table(6, &other)], &palette);
        assert!(logs_contain("OutsideColorTables"));
    }

    /// A blit naming a colour table other than 0 is logged and painted from the palette (#477).
    #[test]
    #[tracing_test::traced_test]
    fn a_blit_naming_another_colour_table_is_logged() {
        let palette = two_colour_palette();
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(4, 1).unwrap();
        run_8bpp(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap_8(0, 0, &[[1, 1, 1, 1]]),
                memblt((0, 0), [0, 0, 1, 1], SRCCOPY, [0, 0]),
            ],
            &palette,
        );
        assert!(!logs_contain("names a colour table other than 0"));
        run_8bpp(
            &mut orders,
            &mut fb,
            &[memblt((0x0100, 0), [1, 0, 1, 1], SRCCOPY, [0, 0])],
            &palette,
        );
        assert!(logs_contain("names a colour table other than 0"));
        assert_eq!(pixel(&fb, 1, 0), [0xFF, 0, 0, 0xFF]);
    }

    fn run(orders: &mut Orders, fb: &mut Framebuffer, parts: &[Vec<u8>]) -> Vec<FrameUpdate> {
        run_with(orders, fb, parts, usize::MAX)
    }

    fn pixel(fb: &Framebuffer, x: usize, y: usize) -> [u8; 4] {
        let at = (y * usize::from(fb.width()) + x) * 4;
        fb.pixels()[at..at + 4].try_into().unwrap()
    }

    fn frame(x: u16, y: u16, width: u16, height: u16) -> FrameUpdate {
        FrameUpdate {
            x,
            y,
            width,
            height,
        }
    }

    const BLACK: [u8; 4] = [0, 0, 0, 255];

    /// A cached bitmap blits at the destination from `(nXSrc, nYSrc)`, a top-down row: the
    /// spec's inverted y addresses bottom-up storage, as FreeRDP's `gdi_memblt` reads it.
    #[test]
    fn memblt_copies_the_cached_source_rectangle() {
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(8, 4).unwrap();
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 1, &[&[RED, GREEN, BLUE], &[WHITE, BLUE, GREEN]]),
                memblt((0, 1), [2, 1, 2, 1], SRCCOPY, [1, 1]),
            ],
        );
        assert_eq!(frames, [frame(2, 1, 2, 1)]);
        assert_eq!(pixel(&fb, 2, 1), rgba(BLUE));
        assert_eq!(pixel(&fb, 3, 1), rgba(GREEN));
        assert_eq!(pixel(&fb, 1, 1), BLACK);
    }

    /// The destination is clipped to the bounds (inclusive), the framebuffer and the source.
    #[test]
    fn memblt_is_clipped_to_bounds_framebuffer_and_source() {
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(8, 4).unwrap();
        let unbounded = memblt((0, 0), [0, 0, 16, 16], SRCCOPY, [0, 0]);
        let mut bounded = vec![unbounded[0] | TS_BOUNDS];
        bounded.extend_from_slice(&unbounded[1..4]);
        bounded.push(0x0F);
        for edge in [1i16, 0, 1, 0] {
            bounded.extend_from_slice(&edge.to_le_bytes());
        }
        bounded.extend_from_slice(&unbounded[4..]);
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&[RED, GREEN, BLUE]]),
                bounded,
                memblt((0, 0), [6, 3, 4, 4], SRCCOPY, [0, 0]),
            ],
        );
        assert_eq!(frames, [frame(1, 0, 1, 1), frame(6, 3, 2, 1)]);
        assert_eq!(pixel(&fb, 1, 0), rgba(GREEN));
        assert_eq!(pixel(&fb, 7, 3), rgba(GREEN));
    }

    /// A ScrBlt with every field and absolute coordinates.
    pub(crate) fn scrblt(dest: [i16; 4], rop: u8, src: [i16; 2]) -> Vec<u8> {
        let mut order = vec![
            TS_STANDARD | TS_TYPE_CHANGE,
            justrdp_pdu::orders::TS_ENC_SCRBLT_ORDER,
            0x7F,
        ];
        for value in dest {
            order.extend_from_slice(&value.to_le_bytes());
        }
        order.push(rop);
        for value in src {
            order.extend_from_slice(&value.to_le_bytes());
        }
        order
    }

    /// A framebuffer whose every pixel is distinct: red is x, green is y.
    fn gradient(width: u16, height: u16) -> Framebuffer {
        let mut fb = Framebuffer::new(width, height).unwrap();
        let mut rgba = Vec::new();
        for y in 0..height {
            for x in 0..width {
                rgba.extend_from_slice(&[x as u8, y as u8, 0x40, 0xFF]);
            }
        }
        fb.blit(0, 0, width, height, &rgba, usize::from(width));
        fb
    }

    /// The reference ScrBlt: the source copied out whole, then written, clipped to the
    /// framebuffer on both sides.
    fn copy_through_a_buffer(fb: &Framebuffer, dest: [i16; 4], src: [i16; 2]) -> Vec<u8> {
        let (w, h) = (i32::from(fb.width()), i32::from(fb.height()));
        let before = fb.pixels().to_vec();
        let mut after = before.clone();
        for dy in 0..i32::from(dest[3]) {
            for dx in 0..i32::from(dest[2]) {
                let (x, y) = (i32::from(dest[0]) + dx, i32::from(dest[1]) + dy);
                let (sx, sy) = (i32::from(src[0]) + dx, i32::from(src[1]) + dy);
                if (0..w).contains(&x)
                    && (0..h).contains(&y)
                    && (0..w).contains(&sx)
                    && (0..h).contains(&sy)
                {
                    let to = ((y * w + x) * 4) as usize;
                    let from = ((sy * w + sx) * 4) as usize;
                    after[to..to + 4].copy_from_slice(&before[from..from + 4]);
                }
            }
        }
        after
    }

    /// Source and destination overlap in all four directions, and the copy reads as if the
    /// whole source was taken first.
    #[test]
    fn scrblt_overlapping_copies_match_a_copy_through_a_buffer() {
        for (dest, src) in [
            ([3, 2, 8, 5], [1, 2]), // right
            ([1, 2, 8, 5], [3, 2]), // left
            ([2, 3, 8, 5], [2, 1]), // down
            ([2, 1, 8, 5], [2, 3]), // up
            ([3, 3, 8, 5], [1, 1]), // down and right
        ] {
            let mut fb = gradient(16, 10);
            let expected = copy_through_a_buffer(&fb, dest, src);
            let mut orders = Orders::new(&capabilities(4, true));
            let frames = run(&mut orders, &mut fb, &[scrblt(dest, SRCCOPY, src)]);
            assert_eq!(fb.pixels(), &expected[..], "dest {dest:?} src {src:?}");
            assert_eq!(frames.len(), 1);
        }
    }

    /// A source partly outside the framebuffer shrinks the destination to what exists, and
    /// one wholly outside paints nothing.
    #[test]
    fn scrblt_sources_outside_the_framebuffer_are_clipped() {
        let mut fb = gradient(16, 10);
        let expected = copy_through_a_buffer(&fb, [0, 0, 8, 8], [12, 6]);
        let mut orders = Orders::new(&capabilities(4, true));
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                scrblt([0, 0, 8, 8], SRCCOPY, [12, 6]),
                scrblt([0, 0, 4, 4], SRCCOPY, [-9, 40]),
            ],
        );
        assert_eq!(frames, [frame(0, 0, 4, 4)]);
        assert_eq!(fb.pixels(), &expected[..]);
    }

    /// A ScrBlt ROP reads the destination before the copy writes it; bounds clip it.
    #[test]
    fn scrblt_rops_read_the_destination_and_bounds_clip() {
        let mut fb = gradient(8, 2);
        let mut orders = Orders::new(&capabilities(4, true));
        // SRCINVERT of a pixel onto itself clears it.
        run(&mut orders, &mut fb, &[scrblt([0, 0, 2, 1], 0x66, [0, 0])]);
        assert_eq!(pixel(&fb, 0, 0), BLACK);
        assert_eq!(pixel(&fb, 1, 0), BLACK);
        assert_eq!(pixel(&fb, 2, 0), [2, 0, 0x40, 0xFF]);
        let unbounded = scrblt([0, 1, 8, 1], SRCCOPY, [0, 0]);
        let mut bounded = vec![unbounded[0] | TS_BOUNDS];
        bounded.extend_from_slice(&unbounded[1..3]);
        bounded.push(0x0F);
        for edge in [4i16, 0, 5, 1] {
            bounded.extend_from_slice(&edge.to_le_bytes());
        }
        bounded.extend_from_slice(&unbounded[3..]);
        let frames = run(&mut orders, &mut fb, &[bounded]);
        assert_eq!(frames, [frame(4, 1, 2, 1)]);
        assert_eq!(pixel(&fb, 4, 1), [4, 0, 0x40, 0xFF]);
        assert_eq!(pixel(&fb, 3, 1), [3, 1, 0x40, 0xFF]);
    }

    /// A Frame Marker of `action`.
    pub(crate) fn frame_marker(action: u32) -> Vec<u8> {
        let mut order = vec![justrdp_pdu::orders::TS_ALTSEC_FRAME_MARKER << 2 | TS_SECONDARY];
        order.extend_from_slice(&action.to_le_bytes());
        order
    }

    /// What a Frame Marker pair brackets reaches the host at the end, in paint order, across
    /// updates; outside a frame each order's rect goes out at once (#462).
    #[test]
    fn a_frame_marker_pair_holds_its_frames_until_the_end() {
        use justrdp_pdu::orders::{TS_FRAME_END, TS_FRAME_START};
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(8, 2).unwrap();
        let held = run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&[RED]]),
                memblt((0, 0), [0, 0, 1, 1], SRCCOPY, [0, 0]),
                frame_marker(TS_FRAME_START),
                memblt((0, 0), [1, 0, 1, 1], SRCCOPY, [0, 0]),
            ],
        );
        assert_eq!(held, [frame(0, 0, 1, 1)], "only the unbracketed one");
        assert_eq!(
            pixel(&fb, 1, 0),
            rgba(RED),
            "the framebuffer is painted at once"
        );
        let released = run(
            &mut orders,
            &mut fb,
            &[
                memblt((0, 0), [2, 0, 1, 1], SRCCOPY, [0, 0]),
                frame_marker(TS_FRAME_END),
                memblt((0, 0), [3, 0, 1, 1], SRCCOPY, [0, 0]),
            ],
        );
        assert_eq!(
            released,
            [frame(1, 0, 1, 1), frame(2, 0, 1, 1), frame(3, 0, 1, 1)]
        );
    }

    /// An end with no start changes nothing, and a second start continues the frame
    /// (ADR-0009 §2); an unknown action is ignored.
    #[test]
    fn unmatched_frame_markers_are_tolerated() {
        use justrdp_pdu::orders::{TS_FRAME_END, TS_FRAME_START};
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(8, 1).unwrap();
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&[RED]]),
                frame_marker(TS_FRAME_END),
                memblt((0, 0), [0, 0, 1, 1], SRCCOPY, [0, 0]),
                frame_marker(7),
                frame_marker(TS_FRAME_START),
                memblt((0, 0), [1, 0, 1, 1], SRCCOPY, [0, 0]),
                frame_marker(TS_FRAME_START),
                memblt((0, 0), [2, 0, 1, 1], SRCCOPY, [0, 0]),
            ],
        );
        assert_eq!(frames, [frame(0, 0, 1, 1)]);
        let frames = run(&mut orders, &mut fb, &[frame_marker(TS_FRAME_END)]);
        assert_eq!(frames, [frame(1, 0, 1, 1), frame(2, 0, 1, 1)]);
    }

    /// A release hands the held rects over and leaves the frame open: its end still closes it
    /// and hands over only what was painted after the release (#470).
    #[test]
    fn a_release_hands_over_an_open_frame_and_keeps_it_open() {
        use justrdp_pdu::orders::{TS_FRAME_END, TS_FRAME_START};
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(8, 1).unwrap();
        assert!(!orders.in_frame());
        assert_eq!(orders.release_held(), [], "no frame, nothing held");
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&[RED]]),
                frame_marker(TS_FRAME_START),
                memblt((0, 0), [0, 0, 1, 1], SRCCOPY, [0, 0]),
            ],
        );
        assert_eq!(frames, []);
        assert!(orders.in_frame());
        assert_eq!(orders.release_held(), [frame(0, 0, 1, 1)]);
        assert!(orders.in_frame(), "the frame stays open");
        assert_eq!(orders.release_held(), [], "nothing twice");
        assert_eq!(orders.frames_ended(), 0, "a release ends nothing");
        let frames = run(
            &mut orders,
            &mut fb,
            &[memblt((0, 0), [1, 0, 1, 1], SRCCOPY, [0, 0])],
        );
        assert_eq!(frames, [], "still held after the release");
        let frames = run(&mut orders, &mut fb, &[frame_marker(TS_FRAME_END)]);
        assert_eq!(
            frames,
            [frame(1, 0, 1, 1)],
            "only what followed the release"
        );
        assert!(!orders.in_frame());
        assert_eq!(orders.frames_ended(), 1);
        run(&mut orders, &mut fb, &[frame_marker(TS_FRAME_END)]);
        assert_eq!(
            orders.frames_ended(),
            1,
            "an end with no start ends nothing"
        );
    }

    /// Past 64 held rects a frame collapses to their bounding box and goes on holding, as
    /// EGFX's does: what reaches the host stays within 64 rects and still covers every one.
    #[test]
    fn a_frame_past_64_rects_collapses_to_their_bounds() {
        use justrdp_pdu::orders::{TS_FRAME_END, TS_FRAME_START};
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(80, 4).unwrap();
        let mut parts = vec![cache_bitmap(0, 0, &[&[RED]]), frame_marker(TS_FRAME_START)];
        for x in 0..70 {
            parts.push(memblt((0, 0), [x + 3, 1, 1, 1], SRCCOPY, [0, 0]));
        }
        parts.push(frame_marker(TS_FRAME_END));
        let frames = run(&mut orders, &mut fb, &parts);
        assert!(frames.len() <= MAX_HELD_RECTS, "{} rects", frames.len());
        assert_eq!(frames[0], frame(3, 1, 65, 1), "the first 65 as one box");
        for x in 3..73u16 {
            assert!(
                frames
                    .iter()
                    .any(|r| (r.x..r.x + r.width).contains(&x) && r.y == 1),
                "column {x} is covered"
            );
        }
    }

    /// A reactivation drops a frame in flight; its pixels are in the framebuffer, which the
    /// reactivation hands the host whole.
    #[test]
    fn a_reactivation_drops_the_frame_in_flight() {
        use justrdp_pdu::orders::{TS_FRAME_END, TS_FRAME_START};
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(4, 1).unwrap();
        run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&[RED]]),
                frame_marker(TS_FRAME_START),
                memblt((0, 0), [0, 0, 1, 1], SRCCOPY, [0, 0]),
            ],
        );
        orders.reactivate();
        assert!(!orders.in_frame());
        assert_eq!(
            orders.frames_ended(),
            1,
            "the dropped frame counts as ended"
        );
        // The next pair releases only what it brackets.
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                frame_marker(TS_FRAME_START),
                memblt((0, 0), [1, 0, 1, 1], SRCCOPY, [0, 0]),
                frame_marker(TS_FRAME_END),
            ],
        );
        assert_eq!(frames, [frame(1, 0, 1, 1)]);
        orders.reactivate();
        assert_eq!(
            orders.frames_ended(),
            2,
            "a reactivation with no frame open drops none"
        );
    }

    /// A miss or an index outside the caches is skipped, and the update goes on.
    #[test]
    fn a_cache_miss_is_skipped_and_the_update_continues() {
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(8, 4).unwrap();
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                memblt((0, 2), [0, 0, 1, 1], SRCCOPY, [0, 0]),
                memblt((0, 4), [0, 0, 1, 1], SRCCOPY, [0, 0]),
                memblt((7, 0), [0, 0, 1, 1], SRCCOPY, [0, 0]),
                cache_bitmap(0, 3, &[&[RED]]),
                cache_bitmap(1, 9, &[&[RED]]),
                memblt((0, 3), [5, 2, 1, 1], SRCCOPY, [0, 0]),
            ],
        );
        assert_eq!(frames, [frame(5, 2, 1, 1)]);
    }

    /// `BITMAPCACHE_WAITING_LIST_INDEX` names one extra entry, apart from the cache's own.
    #[test]
    fn the_waiting_list_entry_is_its_own_slot() {
        let mut orders = Orders::new(&capabilities(1, true));
        let mut fb = Framebuffer::new(4, 1).unwrap();
        let mut waiting = cache_bitmap(0, 0, &[&[BLUE]]);
        // CBR2_DO_NOT_CACHE sits at bit 4 of the flags, bit 11 of extraFlags.
        waiting[4] |= ((orders::CBR2_DO_NOT_CACHE << 7) >> 8) as u8;
        run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&[RED]]),
                waiting,
                memblt((0, 0), [0, 0, 1, 1], SRCCOPY, [0, 0]),
                memblt(
                    (0, BITMAPCACHE_WAITING_LIST_INDEX),
                    [1, 0, 1, 1],
                    SRCCOPY,
                    [0, 0],
                ),
            ],
        );
        assert_eq!(pixel(&fb, 0, 0), rgba(RED));
        assert_eq!(pixel(&fb, 1, 0), rgba(BLUE));
    }

    /// An order of an undecoded type ends the update: what came before it stays applied.
    #[test]
    fn an_undecoded_order_ends_the_update() {
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(4, 1).unwrap();
        let line_to = vec![TS_STANDARD | TS_TYPE_CHANGE, 0x09, 0x00, 0x00];
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&[RED]]),
                memblt((0, 0), [0, 0, 1, 1], SRCCOPY, [0, 0]),
                line_to,
                memblt((0, 0), [1, 0, 1, 1], SRCCOPY, [0, 0]),
            ],
        );
        assert_eq!(frames.len(), 1);
        assert_eq!(pixel(&fb, 1, 0), BLACK);
    }

    /// ROPs other than SRCCOPY read the destination; Mem3Blt's brush is the pattern.
    #[test]
    fn rops_read_the_destination_and_the_brush() {
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(4, 2).unwrap();
        run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&[RED, RED], &[GREEN, GREEN]]),
                memblt((0, 0), [0, 0, 2, 2], SRCCOPY, [0, 0]),
                // SRCINVERT of the same source clears it to black.
                memblt((0, 0), [0, 0, 1, 1], 0x66, [0, 0]),
                // PATCOPY with a solid brush paints the foreground.
                mem3blt(
                    (0, 0),
                    [1, 0, 1, 1],
                    0xF0,
                    [WHITE, BLUE],
                    [0, 0, rop::BS_SOLID, 0],
                ),
                // PATCOPY with HS_HORIZONTAL from origin (0, -3): pattern row 3 is the line,
                // the foreground, and lands on row 0; row 1 is background.
                mem3blt(
                    (0, 0),
                    [0, 0, 1, 2],
                    0xF0,
                    [WHITE, BLUE],
                    [0, (-3i8) as u8, rop::BS_HATCHED, 0],
                ),
            ],
        );
        assert_eq!(pixel(&fb, 1, 0), rgba(BLUE));
        assert_eq!(pixel(&fb, 0, 0), rgba(BLUE));
        assert_eq!(pixel(&fb, 0, 1), rgba(WHITE));
        assert_eq!(pixel(&fb, 1, 1), rgba(GREEN));
        // And the SRCINVERT did run: replay it on a fresh framebuffer.
        let mut fb = Framebuffer::new(1, 1).unwrap();
        run(
            &mut orders,
            &mut fb,
            &[
                memblt((0, 0), [0, 0, 1, 1], SRCCOPY, [0, 0]),
                memblt((0, 0), [0, 0, 1, 1], 0x66, [0, 0]),
            ],
        );
        assert_eq!(pixel(&fb, 0, 0), BLACK);
    }

    /// A Mem3Blt whose brush cannot be drawn paints nothing; one that was not advertised is
    /// painted all the same (ADR-0009 §2: accept-and-log).
    #[test]
    fn unsupported_brushes_paint_nothing_and_unadvertised_orders_paint() {
        let mut fb = Framebuffer::new(2, 1).unwrap();
        let mut orders = Orders::new(&capabilities(4, true));
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&[RED]]),
                mem3blt(
                    (0, 0),
                    [0, 0, 1, 1],
                    0xF0,
                    [WHITE, BLUE],
                    [0, 0, rop::TS_CACHED_BRUSH | 1, 0],
                ),
                mem3blt(
                    (0, 0),
                    [0, 0, 1, 1],
                    0xF0,
                    [WHITE, BLUE],
                    [0, 0, rop::BS_NULL, 0],
                ),
                mem3blt(
                    (0, 0),
                    [0, 0, 1, 1],
                    0xF0,
                    [WHITE, BLUE],
                    [0, 0, rop::BS_HATCHED, 6],
                ),
            ],
        );
        assert!(frames.is_empty());
        let mut orders = Orders::new(&capabilities(4, false));
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&[RED]]),
                mem3blt((0, 0), [0, 0, 1, 1], SRCCOPY, [WHITE, BLUE], [0; 4]),
            ],
        );
        assert_eq!(frames, [frame(0, 0, 1, 1)]);
    }

    /// A bitmap of more pixels than its cache's entry is not stored, and its entry is emptied;
    /// one wider or taller than the tile's side but within the entry is.
    #[test]
    fn a_bitmap_past_its_cache_entry_size_is_not_cached() {
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(32, 16).unwrap();
        // Wider than cache 0's 16-pixel tile side, inside its 256-pixel entry.
        let wide = vec![RED; 17];
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&wide]),
                memblt((0, 0), [0, 0, 17, 1], SRCCOPY, [0, 0]),
            ],
        );
        assert_eq!(frames, [frame(0, 0, 17, 1)]);
        // Exactly the entry, 16x16: stored.
        let side = vec![GREEN; 16];
        let rows: Vec<&[u16]> = vec![&side; 16];
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 1, &rows),
                memblt((0, 1), [0, 0, 16, 16], SRCCOPY, [0, 0]),
            ],
        );
        assert_eq!(frames, [frame(0, 0, 16, 16)]);
        // 17x16 pixels pass the entry: not stored, and the entry is emptied.
        let rows: Vec<&[u16]> = vec![&wide; 16];
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &rows),
                memblt((0, 0), [0, 0, 1, 1], SRCCOPY, [0, 0]),
            ],
        );
        assert_eq!(frames, []);
    }

    /// Past the budget nothing more is painted or decoded, but every order still advances the
    /// history, and an entry the budget refused misses instead of keeping its old bitmap.
    #[test]
    fn past_the_budget_orders_are_decoded_but_not_painted() {
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(4, 1).unwrap();
        // 4 bytes per pixel: two cache fills and one MemBlt fit in 12.
        let frames = run_with(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&[RED]]),
                cache_bitmap(0, 1, &[&[RED]]),
                memblt((0, 0), [0, 0, 1, 1], SRCCOPY, [0, 0]),
                cache_bitmap(0, 0, &[&[BLUE]]),
                memblt((0, 1), [1, 0, 1, 1], SRCCOPY, [0, 0]),
            ],
            12,
        );
        assert_eq!(frames, [frame(0, 0, 1, 1)]);
        let frames = run(
            &mut orders,
            &mut fb,
            &[memblt((0, 0), [2, 0, 1, 1], SRCCOPY, [0, 0])],
        );
        assert!(frames.is_empty(), "the refused entry misses");
    }

    /// TS_COLOR at 16 bpp is the pixel itself, at 24 and 32 the red, green, blue bytes.
    #[test]
    fn order_colors_follow_the_session_depth() {
        let palette = Palette::default();
        let color = |value, bpp| match order_color(value, &palette, bpp) {
            Ok(color) => color.to_le_bytes(),
            Err(_) => panic!("{value:#x} at {bpp} bpp"),
        };
        assert_eq!(color(u32::from(RED), 16), rgba(RED));
        assert_eq!(color(0x33_2211, 24), [0x11, 0x22, 0x33, 0xFF]);
        assert_eq!(color(0x33_2211, 32), [0x11, 0x22, 0x33, 0xFF]);
    }

    proptest::proptest! {
        /// Arbitrary order data after a cache fill never panics the paint path (ADR-0008).
        #[test]
        fn orders_never_panic(
            number_orders in 0u16..64,
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512),
            glyphs in proptest::prelude::any::<bool>(),
        ) {
            let sets = if glyphs { glyph_capabilities() } else { capabilities(4, true) };
            let mut orders = Orders::new(&sets);
            let mut fb = Framebuffer::new(16, 8).unwrap();
            let mut bytes = cache_bitmap(0, 0, &[&[RED, GREEN], &[BLUE, WHITE]]);
            bytes.extend_from_slice(&data);
            let mut frames = Vec::new();
            let _ = orders.apply(
                OrdersUpdate { number_orders: number_orders + 1, order_data: &bytes },
                &mut fb,
                &Palette::default(),
                16,
                16 * 8 * 4 * 2,
                &mut frames,
            );
        }
    }
}
