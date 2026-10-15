//! Drawing orders in the session (`[MS-RDPEGDI]` 3.2.5.1): the Revision 2 bitmap caches the
//! Cache Bitmap orders fill, and MemBlt and Mem3Blt painting from them into the framebuffer.
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
    self, BITMAPCACHE_WAITING_LIST_INDEX, CacheBitmapRev2, Clip, DrawingOrder, Mem3Blt, MemBlt,
    OrderError, OrderHistory, OrdersUpdate,
};

/// ROP3 SRCCOPY: the source, unchanged.
const SRCCOPY: u8 = 0xCC;

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
    /// A bitmap larger than its cache's tile size.
    OversizedBitmap,
    /// A brush this session cannot draw: cached, hollow under a ROP that reads the pattern, or
    /// a hatch outside the six.
    UnsupportedBrush,
    /// The update's paint budget is spent.
    OverBudget,
}

/// The connection's drawing-order state: the primary order history, the bitmap caches and which
/// blits were advertised. A Deactivation–Reactivation keeps the caches and resets the history
/// ([`Self::reset_history`]).
#[derive(Debug)]
pub(crate) struct Orders {
    history: OrderHistory,
    /// Each advertised Revision 2 cache, its entries followed by one waiting-list entry.
    caches: Vec<Vec<Option<CachedBitmap>>>,
    memblt: bool,
    mem3blt: bool,
}

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
        Self {
            history: OrderHistory::default(),
            caches,
            memblt: support.is_some_and(|s| s[capability::ORDER_NEG_MEMBLT_INDEX] != 0),
            mem3blt: support.is_some_and(|s| s[capability::ORDER_NEG_MEM3BLT_INDEX] != 0),
        }
    }

    /// Forget the primary order history (a Deactivation–Reactivation).
    pub(crate) fn reset_history(&mut self) {
        self.history = OrderHistory::default();
    }

    /// Apply one Orders Update, pushing a [`FrameUpdate`] for each order that painted.
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
                DrawingOrder::MemBlt { order, clip } => self.blt(
                    self.memblt,
                    &order,
                    None,
                    clip,
                    framebuffer,
                    palette,
                    bits_per_pixel,
                    &mut budget,
                    frames,
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
                    frames,
                ),
                DrawingOrder::SkippedSecondary { order_type } => {
                    tracing::debug!(
                        target: "rdp_orders",
                        order_type,
                        "a secondary drawing order of a type not decoded, skipped"
                    );
                    Ok(())
                }
            };
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
        if width > tile || height > tile {
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
        let clip = match clip {
            Clip::None => None,
            Clip::Bounds(bounds) => Some(bounds),
            Clip::Unknown => return Err(NotApplied::Skipped(Skip::UnknownClip)),
        };
        let pattern = match mem3blt {
            Some(order) if rop::uses_pattern(order.blt.rop) => {
                Some(pattern(order, palette, bits_per_pixel)?)
            }
            _ => None,
        };
        // The low byte is the cache; the high byte, a color table entry, is not read.
        let cache_id = order.cache_id & 0x00FF;
        let bitmap = self
            .slot(cache_id, order.cache_index)?
            .as_ref()
            .ok_or(NotApplied::Skipped(Skip::CacheMiss))?;
        // The destination, clipped to the framebuffer, the bounds and the source bitmap.
        let mut left = i32::from(order.left);
        let mut top = i32::from(order.top);
        let mut right = left + i32::from(order.width);
        let mut bottom = top + i32::from(order.height);
        let shift_x = i32::from(order.x_src) - left;
        let shift_y = i32::from(order.y_src) - top;
        left = left.max(0).max(-shift_x);
        top = top.max(0).max(-shift_y);
        right = right
            .min(i32::from(framebuffer.width()))
            .min(i32::from(bitmap.width) - shift_x);
        bottom = bottom
            .min(i32::from(framebuffer.height()))
            .min(i32::from(bitmap.height) - shift_y);
        if let Some(bounds) = clip {
            left = left.max(i32::from(bounds.left));
            top = top.max(i32::from(bounds.top));
            right = right.min(i32::from(bounds.right) + 1);
            bottom = bottom.min(i32::from(bounds.bottom) + 1);
        }
        if left >= right || top >= bottom {
            return Ok(());
        }
        let (width, height) = ((right - left) as usize, (bottom - top) as usize);
        if !charge(budget, width * height * 4) {
            return Err(NotApplied::Skipped(Skip::OverBudget));
        }
        let source_stride = usize::from(bitmap.width) * 4;
        let target_stride = usize::from(framebuffer.width()) * 4;
        let mut block = vec![0u8; width * height * 4];
        for row in 0..height {
            let y = top as usize + row;
            let source_row = (y as i32 + shift_y) as usize * source_stride;
            let source_start = source_row + (left + shift_x) as usize * 4;
            let source = &bitmap.rgba[source_start..source_start + width * 4];
            let out = &mut block[row * width * 4..(row + 1) * width * 4];
            if order.rop == SRCCOPY {
                out.copy_from_slice(source);
                continue;
            }
            let target_start = y * target_stride + left as usize * 4;
            let target = &framebuffer.pixels()[target_start..target_start + width * 4];
            for column in 0..width {
                let at = column * 4;
                let p = pattern.map_or(0, |p| p.pixel(left + column as i32, y as i32));
                let s = word(&source[at..at + 4]);
                let d = word(&target[at..at + 4]);
                out[at..at + 4].copy_from_slice(&rop::rop3(order.rop, p, s, d).to_le_bytes());
            }
        }
        if let Some(frame) = framebuffer.blit(
            left as u16,
            top as u16,
            width as u16,
            height as u16,
            &block,
            width,
        ) {
            frames.push(frame);
        }
        Ok(())
    }
}

/// Why an order was not applied: skipped, or failed on malformed data.
enum NotApplied {
    Skipped(Skip),
    Failed(crate::SessionError),
}

fn word(pixel: &[u8]) -> u32 {
    u32::from_le_bytes([pixel[0], pixel[1], pixel[2], pixel[3]])
}

/// A Mem3Blt's brush, ready to paint.
fn pattern(order: &Mem3Blt, palette: &Palette, bits_per_pixel: u16) -> Result<Pattern, NotApplied> {
    let brush = &order.brush;
    let fore = order_color(order.fore_color, palette, bits_per_pixel)?;
    let back = order_color(order.back_color, palette, bits_per_pixel)?;
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

    /// The capability sets with MemBlt (and Mem3Blt) over three Revision 2 caches of `entries`.
    pub(crate) fn capabilities(entries: u32, mem3blt: bool) -> Vec<CapabilitySet> {
        let mut order = OrderCapabilitySet::default();
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
        let opaque_rect = vec![TS_STANDARD | TS_TYPE_CHANGE, 0x0A, 0x00];
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&[RED]]),
                memblt((0, 0), [0, 0, 1, 1], SRCCOPY, [0, 0]),
                opaque_rect,
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

    /// A bitmap larger than its cache's tile is not stored, and its entry is emptied.
    #[test]
    fn a_bitmap_past_its_tile_size_is_not_cached() {
        let mut orders = Orders::new(&capabilities(4, true));
        let mut fb = Framebuffer::new(32, 1).unwrap();
        let frames = run(
            &mut orders,
            &mut fb,
            &[
                cache_bitmap(0, 0, &[&[RED]]),
                cache_bitmap(0, 0, &[&[RED; 17]]),
                memblt((0, 0), [0, 0, 1, 1], SRCCOPY, [0, 0]),
                cache_bitmap(1, 0, &[&[RED; 17]]),
                memblt((1, 0), [0, 0, 17, 1], SRCCOPY, [0, 0]),
            ],
        );
        assert_eq!(frames, [frame(0, 0, 17, 1)]);
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
        ) {
            let mut orders = Orders::new(&capabilities(4, true));
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
