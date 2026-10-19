# Drawing orders

## What it is

The GDI drawing orders of `[MS-RDPEGDI]`: compact paint commands a server sends in an Orders
Update on either transport, decoded against a history of the previous orders, painting from caches
the server fills. What is built is what the two measured servers send: Cache Bitmap (Revision 2)
fills a Revision 2 bitmap cache, and MemBlt and Mem3Blt blit from it with a ROP3, Mem3Blt through
an 8×8 brush. `justrdp-pdu::orders` holds the wire format, `justrdp-codecs::rop` the raster
operations and brushes, and `justrdp::orders` the caches and the paint. ScrBlt copies within the
framebuffer (#461), and Frame Markers bracket what the host is handed as one frame (#462).
DstBlt, PatBlt and OpaqueRect fill rectangles (#475), and GlyphIndex draws text from ten glyph
caches that Cache Glyph fills (#476). Epic #22 (the bitmap cache half is
#28's); #460 is the first slice.

## Governing decisions

- [ADR-0016](../../adr/0016-policy-flags-are-the-hosts.md) — whether to advertise orders, the
  cache layout and the colour depth are the host's; the core refuses an advertisement it cannot
  honour (`advertise.rs`).
- [ADR-0009](../../adr/0009-tolerant-negotiation-posture.md) — the receive posture. Its §2
  decided accept-and-log for unannounced orders before any existed; a decodable order the client
  did not advertise is painted with a warning, against 3.2.5.1.1.1's SHOULD ignore.
- [ADR-0003](../../adr/0003-phased-codecs-differential-oracle.md) (Amendment) — owned basis,
  then FreeRDP as tie-break, which settled the two readings under *Reference behaviour*.
- [ADR-0008](../../adr/0008-robustness-testing-fuzz-and-property.md) — no-panic properties on
  the decoder and the paint path, and the `orders` and `session_orders` fuzz targets.

## Design model

- **A primary order has no length, so an undecoded one ends the update.** Its field-flag width
  depends on its type, so nothing after it can be found (3.2.5.1.1.1 step 2 says processing
  ceases). Every order before it is already applied. A secondary order carries its length and is
  skipped whole; an alternate secondary order has none, so one of a type not decoded (every one
  but Frame Marker) ends the update like a primary one.
- **The history keeps decoding past what is not painted.** A cache miss, an out-of-range cache
  id or index, a brush that cannot be drawn and the paint budget skip the paint, never the decode,
  so the field records stay in step with the server's (3.2.5.1.1.1 step 4: ignore the order).
- **The first order past the paint budget ends the update's painting** (#494). Every order after
  it is decoded and nothing after it paints, not even a smaller one that would fit, as the bitmap
  and Surface Commands paths stop. A cache fill after it empties its entry (#498).
- **An undecoded order may have moved the bounds.** When one carries `TS_BOUNDS` without
  `TS_ZERO_BOUNDS_DELTAS`, the history marks the rectangle unknown, every later bounded order
  decodes with `Clip::Unknown` and is not painted, until a `bounds` field gives all four edges
  absolutely.
- **The bitmap cache is connection state; the history is reset at each reactivation.** The spec
  says neither. FreeRDP's `update_reset_state` clears the primary history at every finalization
  step and leaves the bitmap cache, and `on_demand_active` does the same.
- **The waiting-list index is an extra entry per cache.** `BITMAPCACHE_WAITING_LIST_INDEX`
  (32767) names one slot past the cache's own entries, never the last real one, as FreeRDP's
  `bitmap_cache_put` allocates it; a `CBR2_DO_NOT_CACHE` fill goes there.
- **A cache entry holds as many pixels as its tile**, `16 << cacheId` squared: `[MS-RDPEGDI]`
  3.1.1.1.1's table sizes each entry in bytes (the tile's pixels at the session's depth), not by
  side. So a cache's decoded size is bounded by the host's entry counts. A fill with more pixels
  is refused and its entry emptied, so a later MemBlt misses rather than painting the bitmap that
  was there before. The budget does the same: past it a fill empties its entry. Until #475 each
  side was held to the tile's, which no WS2019 fill ever crossed; xrdp puts the last 12 rows of a
  64-wide image in cache 1 as 64×12 and 48×12 tiles (768 and 576 pixels, under 1,024), and the
  side rule dropped them. Fixing it in #475 was the maintainer's call (2026-10-16).
- **One `orderSupport` index negotiates PatBlt and OpaqueRect** (`TS_NEG_PATBLT_INDEX`,
  `[MS-RDPBCGR]` 2.2.7.1.3; `[MS-RDPEGDI]` 2.2.2.2.1.1.2.3: "support for PatBlt implies support
  for OpaqueRect"), so the two arrived together (#475). OpaqueRect's colour is three one-byte
  fields, each replacing its own byte of the colour the history holds, as FreeRDP's
  `update_read_opaque_rect_order` merges them; it fills with that colour as PATCOPY. PatBlt runs
  its brush through its ROP with no source, sharing Mem3Blt's brush; a cached brush is skipped,
  as for Mem3Blt, unless the ROP never reads the brush.
- **MultiOpaqueRect is OpaqueRect's colour over a list of rectangles** (#485), up to 45, in a
  Delta-Encoded Rectangles field (2.2.2.2.1.1.1.5). A rectangle's left and top are deltas from
  the rectangle before, the first from `(0, 0)`; its width and height are values, not deltas,
  and an absent one is the previous rectangle's (0 for the first). The spec's prose reads as if
  all four were deltas; its own example (4.1.6) and FreeRDP's `update_read_delta_rects` agree on
  this reading, which is followed. The list lives in the history: an order without one paints the
  first `nDeltaEntries` of the last, and asking for more than it holds is a typed error, as in
  FreeRDP, as is a count past 45. The list is read inside its `cbData`, where FreeRDP reads it
  from the stream and ignores `cbData`; the two differ only on a server whose `cbData` is wrong,
  which none has been seen to send. Each rectangle is filled as OpaqueRect is, through the
  bounds, a frame each; an empty one paints nothing, as FreeRDP skips the empty rectangles
  "older windows servers tend to send". The order's own `nLeftRect` … `nHeight` is the union of
  the list in the spec's example and is not painted, as in FreeRDP. It has its own
  `orderSupport` index, 0x12.
- **The 2008 R2 VM sends MultiOpaqueRect only to a client advertising the offscreen bitmap
  cache** (2026-10-19). FreeRDP on its logon screen got 2 with every cache, 2 without the glyph
  or the brush cache, and none without the offscreen cache, when it got what justrdp gets: 382
  MemBlt and 4 OpaqueRect. The server draws its shapes on offscreen surfaces and blits them to
  the screen. Shipping it on the spec's example and FreeRDP, its real-server proof left to the
  offscreen orders (#489), was the maintainer's call (2026-10-19), made over holding the branch
  until #489 and folding it into #489. #489 then brought one on the logon screen, inside the
  comparison below.
- **Polyline draws a pen through its points as FreeRDP's `gdi_LineTo` does** (#488). The spec
  does not say which pixels a line covers, so FreeRDP's rule is followed:
  - Each segment is a Bresenham walk (`e = dx - dy`) that leaves out its end, so each vertex is
    drawn once, as the start of the next segment, and the last is not drawn.
  - `bRop2` runs through the ROP3 table with the pen as the source, code `(bRop2 - 1) × 0x11`.
    A value outside the sixteen paints nothing, as FreeRDP's `gdi_rop_color` writes nothing for
    one.
  - The points are deltas from the point before, kept in the history, which an order without a
    list reuses. A list of no points, or a count past the list held, is a typed error, as in
    FreeRDP.
  - Each segment charges the paint budget the larger of the steps it walks, inside the clip or
    not, and its box inside the clip, which its frame covers; that bounds both a hostile line's
    walk and what the host copies. Each segment delivers the bounding box of the pixels it drew.
  - FreeRDP's `R2_MERGEPENNOT` computes `src | ~pen`, the same as `R2_MERGENOTPEN`; the spec's
    PDno is `pen | ~dst`, which the ROP3 table gives.
- **Offscreen bitmaps are held in the core, as RGBA framebuffers** (#489). The surface model, its
  bounds and the out-of-range Switch were the maintainer's calls of 2026-10-19, recorded with what
  they were decided on in #489's body:
  - `Orders` keeps the advertised entries and a target: the screen, an offscreen bitmap, or
    unknown. Every paint order paints the target.
  - Only a paint on the screen delivers a `FrameUpdate`. Frame Marker held rects and the
    open-frame release (#470) therefore see only the screen.
  - A MemBlt whose `cacheId` low byte is 0xFF reads offscreen bitmap `cacheIndex`. One that reads
    its own target is safe as it stands, since `compose` builds the whole block before `blit`
    writes it.
  - ScrBlt reads the screen whatever the target (2.2.2.2.1.1.2.7, and FreeRDP's `gdi_scrblt`).
  - A Create Offscreen Bitmap replaces its entry with a black bitmap, then empties its delete
    list's entries (FreeRDP's order). The delete list applies even when the Create makes
    nothing. A Create at the target's id leaves the new bitmap the target.
  - **The advertised size is enforced**, in KB counted at the session's depth as the server
    counts it, and so is the entry count. The size leaves out the entries the Create replaces and
    deletes, since a delete list is how the server makes room. The bitmaps are RGBA, so they hold
    twice the advertised size at 16 bpp and four times at 8 bpp.
  - **A Create past either flushes every bitmap and turns offscreen off for the session.** The
    session sends one Offscreen Bitmap Cache Error PDU (`OC_ERR_FLUSH_AND_DISABLE_OFFSCREEN`,
    2.2.2.3.2). FreeRDP enforces only the count.
  - **A target that was a bitmap paints nothing** until the next Switch, as a Switch to a
    flushed bitmap would (#494). Orders the server meant for the bitmap do not land on the
    screen. Whether the server stops using offscreen after the PDU is unmeasured (#497): at a
    budget of 1 it went on switching to the flushed bitmaps.
  - **A Switch to an entry never created, or past the entries, makes the target unknown.** Paint
    orders are then skipped until the next Switch, as a cache index out of range is (ADR-0009
    §2). The spec says to drop the connection.
  - **Without the cache advertised**, Create and Switch are ignored (3.2.5.1.3.1.1 and .2).
  - **A Create of no pixels empties its entry.** FreeRDP's decoder refuses it instead.
  - **A Deactivation-Reactivation keeps the bitmaps and returns the target to the screen**, as
    the bitmap caches are kept. FreeRDP's `update_reset_state` resets only the order history, and
    its caches live for the connection.
  - **Each Create's `cx × cy × 4` bytes are charged to the update's paint budget.** A Create the
    budget cannot buy empties its entry and nothing else (the maintainer's call, #494,
    2026-10-19). There is no flush, no error PDU, and the cache is kept.
    - **What it replaces.** #489's call refused such a Create as one past the cache, with the
      error PDU. That call was made on the size of a single Create alone.
    - **What the new call was shown.** At a budget of 1, the server went on switching to the
      flushed bitmaps after the error PDU: 14 Switches and 176 paints skipped.
    - **The consequence.** The id misses until the server makes it again.
  - The allow-list accepts `offscreenSupportLevel` TRUE only, and only with MemBlt (3.2.5.1.3.1.1).
- **DstBlt runs only destination ROPs.** 2.2.2.2.1.1.2.1 says its ROP MUST depend on the
  destination alone, which leaves BLACKNESS, DSTINVERT, the no-op and WHITENESS; any other is a
  server self-inconsistency and the order is skipped (ADR-0009 §2). That is a derivation, not a
  call anyone made: FreeRDP's `gdi_dstblt` runs such a ROP anyway. No measured server has sent a DstBlt. It is
  built because xrdp 0.9.24 draws in orders only for a client advertising DstBlt, PatBlt, ScrBlt
  and MemBlt all four (`xrdp_caps.c`, `no_orders_supported`); without DstBlt, justrdp got 38 bitmap
  updates and no order (2026-10-16). Building it in #475 was the maintainer's call that day, over a
  slice of its own first, or #475 with no real-server proof.
- **GlyphIndex was decoded before it was drawn** (#475). A primary order of an undecoded type
  ends its update, and xrdp sends GlyphIndex and Cache Glyph whatever the client advertises:
  with the glyph cache off, FreeRDP logged "SERVER BUG ... not announced" for Cache Glyph, and
  with `/relax-order-checks` still received 16 GlyphIndex. Two of justrdp's updates ended there,
  losing the logo, the labels, the input boxes and the buttons, so #475 decoded it and skipped it
  (the maintainer's call, 2026-10-16, over finishing on that weaker measurement or doing #476
  first). Its rectangles and origin are plain 16-bit integers, never deltas, and an order without
  `VariableBytes` reuses the last one's, as FreeRDP's `update_read_glyph_index_order` reads them;
  the history keeps those bytes (`OrderHistory::glyph_index_data`), since an order borrows only
  its update.
- **Glyphs are drawn as FreeRDP places them, and painted as the spec says** (#476).
  - Cache Glyph is Revision 1 (`GLYPH_SUPPORT_PARTIAL` and `FULL` mean the same,
    `[MS-RDPBCGR]` 2.2.7.1.8); Revision 2 belongs to `ENCODE`, which FreeRDP also tells apart by
    the negotiated level, not by the order, so `ENCODE` is refused. A glyph's bitmap is one bit
    per pixel, most significant first, in whole-byte rows padded to four bytes. A glyph outside
    the advertised caches or past its cache's cells is not stored.
  - A glyph sits at the origin plus its offset. Its advance is `ulCharInc` when set, its width
    under `SO_CHAR_INC_EQUAL_BM_BASE`, and otherwise the delta byte after its index (0x80 and two
    more for a long one), added before the glyph is drawn, as FreeRDP's `update_glyph_offset`
    does. xrdp writes exactly that: each glyph's delta is the previous glyph's advance, the first
    0. FreeRDP never advances by `ulCharInc`; justrdp does, as the field's definition and #476's
    acceptance say, and a glyph missing from the cache still takes its cell. That is a derivation
    nothing measured: no measured server sets `ulCharInc`, nor `SO_VERTICAL` or `SO_REVERSED`, and
    `SO_REVERSED` is ignored, as FreeRDP ignores it.
  - Unless `fOpRedundant`, the opaque rectangle fills in `ForeColor` first; the glyphs' set bits
    paint in `BackColor` (the spec's own naming: back is the text), clipped to the text
    rectangle and the order's bounds. Both rectangles are inclusive and empty unless right and
    bottom pass left and top, as FreeRDP measures them. The bits are tested only where the glyph
    overlaps the painted area, which the budget charges. Besides the `ulCharInc` advance, two
    FreeRDP behaviours are not followed, each on the spec's side and xrdp's screen: FreeRDP also fills each glyph's own cell in
    `ForeColor` when the rectangle is not redundant (xrdp sets `fOpRedundant` 0 with an empty
    opaque rectangle, and its bitmap screen has no such boxes), and it keeps the previous text
    colour when it is.
  - Fragments are not kept: the advertisement refuses a fragment cache, and a USE or ADD ends the
    glyph run. The spec and FreeRDP read them differently (an ADD stores the bytes before it in
    the spec, the buffer from its start in FreeRDP; a USE is followed by a delta in the spec, not
    in FreeRDP), xrdp never sends one, and so nothing could settle which is right. #476 allowed
    refusing them.
  - xrdp fills glyph caches 7 to 11, slots 0 to 249 (`xrdp_cache.c`), oldest first. Caches 10
    and 11 lie outside 2.2.2.2.1.1.2.13's 0 to 9, and their glyphs are skipped; the login screen
    uses only cache 7.
- **`nYSrc` is a top-down row of the cached bitmap.** The spec's formula
  (`ActualYSrc = (SourceBitmapHeight − nHeight) − nYSrc`) addresses bottom-up storage; the cache
  stores top-down RGBA, so it uses the field as sent, as FreeRDP's `gdi_memblt` does.
- **ScrBlt reads its whole source before it writes.** Its source is the framebuffer it paints, and
  a moved or scrolled window overlaps it, so the source rectangle is copied out first; the copy
  then goes through the same clipping and composition as MemBlt (`clip_blt`, `compose`), the
  source being the framebuffer.
- **A source past the edge shrinks the destination.** MemBlt and ScrBlt both clip the destination
  to where the source exists. FreeRDP's `adjust_src_coordinates` instead moves an overhanging
  source back inside and copies from there; nothing in this server's traffic reaches the case.
- **A Frame Marker pair holds its rects until the end** (#462, the maintainer's call of
  2026-10-16). The framebuffer is painted as each order arrives; the `FrameUpdate`s of the orders
  between `TS_FRAME_START` and `TS_FRAME_END` are held, across updates, and handed over at the
  end in paint order, collapsing to one bounding box past 64 as the Graphics Pipeline's frames
  do. The call was made over three options, shown with their costs: this; FreeRDP's, whose
  `gdi_frame_marker` does nothing and hands every rect over at once; and holding with a new
  bound. It did not decide what happens to a start whose end never comes (#470, below), nor the
  Surface Commands frame marker, a different message.
- **A frame whose end never comes is the host's to release** (#470, the maintainer's call of
  2026-10-16). `SessionStateMachine::release_open_frames` hands the held rects over and leaves the
  frame open; its end, if it comes, hands over only what was painted after. The `justrdp-tokio`
  runners release after 1 s ([Adapter drive loop](adapter-drive-loop.md)). A Graphics Pipeline
  frame open at the same time is released by the same call.
- **Unmatched markers are tolerated** (ADR-0009, Amendment 2026-10-16): a start inside a frame
  continues it, and an end with no start and an action that is neither are ignored.
- **A frame's held rects die with the framebuffer they name.** A reactivation drops the frame in
  flight, whose pixels the reactivation's full frame carries; a Graphics Pipeline resize
  (`OutputResized`) drops the held rects and leaves the frame open, so its end still closes it.
  Before #462 no rect outlived the update that painted it, so the resize path had nothing to drop.
- **Other paths do not wait for an order frame.** A bitmap update, Set Surface Bits or the
  Graphics Pipeline painting while an order frame is open hands its rects over at once, ahead of
  the order rects held for the end. No pixel is wrong, since a `FrameUpdate` names a region of
  the framebuffer and carries none; the host is told in a different order than things were
  painted. No server is known to mix them.
- **ROP3 is one evaluator.** An index is its own truth table, so `rop3` covers all 256 bitwise
  over RGBA words, alpha forced opaque. MemBlt's ROP must not read the pattern (2.2.2.2.1.1.2.9);
  if one does, the pattern is black. ScrBlt has no brush either, and the same holds for it.
- **Every session decodes Orders Updates, advertised or not.** Before #460 an Orders Update fell
  to the dispatch's catch-all unread; now a malformed one is a `SessionError` even in a session
  that advertised no order (ADR-0009 §3(a): a tolerated order with a malformed body is still a
  typed error). With no Revision 2 set every blit misses, so an unadvertised MemBlt paints only
  in a config `check` never saw.
- **The colour depth is the server's.** `ServerAnnouncement::bits_per_pixel` comes from its
  Demand Active, the client's Bitmap set only when that is 0. `check_orders` refuses orders below
  8 bpp on the client's side.
- **At 8 bpp the colours are the session palette's, as FreeRDP has them** (#477, the
  maintainer's call of 2026-10-16). A cached bitmap's indices resolve through the palette of the
  last Update Palette when it is filled, and an order's colour index through it when it paints.
  `[MS-RDPEGDI]` says otherwise: six Color Table Cache entries, filled by Cache Color Table
  (2.2.2.2.1.2.4), the entry a blit uses named by its `cacheId`'s high byte. FreeRDP 3.32.1 stores
  those tables (`palette_cache_put`) and reads them nowhere. The call was made over the spec's
  way, keeping 8 bpp bitmaps as indices and resolving them at the blit, after a measurement that
  could not tell the two apart: xrdp 0.9.24 sends one Update Palette and one Cache Color Table,
  entry 0, equal to the palette in all 256 colours (read blue, green, red, pad), and every blit
  names entry 0. So Cache Color Table is decoded and paints nothing, and the two signs that a
  server means it are logged at `rdp_orders` warn: a table unlike the palette, and a blit naming
  an entry other than 0. An entry past the six is skipped. Below 8 bpp is still refused,
  unmeasured. xrdp sends its colour table to a session that advertises no order too, and sends
  its Update Palette before the table, so the table is compared with the palette it was made
  from. A table that came before any Update Palette would be compared with the default all-black
  palette, and an order painted before one paints from that palette, without a skip; a derivation
  that no measured server reaches.
- **Advertising the Revision 2 cache requires MemBlt *and* Mem3Blt.** `[MS-RDPBCGR]`
  2.2.7.1.4.2: a client MUST support both to receive Cache Bitmap (Revision 2). The census saw no
  Mem3Blt, but the obligation is the advertisement's, so the brush path is built.

## Code

- `justrdp-pdu/src/orders.rs` — `decode_order`, `OrderHistory`, `OrdersUpdate`, `DrawingOrder`,
  `Clip`, `DstBlt`, `PatBlt`, `OpaqueRect`, `MultiOpaqueRect`, `MAX_DELTA_RECTS`, `ScrBlt`,
  `MemBlt`, `Mem3Blt`, `GlyphIndex`, `Polyline`, `Brush`,
  `CacheBitmapRev2`, `CacheGlyph`, `GlyphData`, `CreateOffscreenBitmap`, `OrderError`,
  `TS_ALTSEC_FRAME_MARKER`, `TS_ALTSEC_SWITCH_SURFACE`, `TS_ALTSEC_CREATE_OFFSCR_BITMAP`,
  `SCREEN_BITMAP_SURFACE`
- `justrdp-pdu/src/share.rs` — `PDU_TYPE2_OFFSCRCACHE_ERROR`, `OC_ERR_FLUSH_AND_DISABLE_OFFSCREEN`
- `justrdp-pdu/src/capability.rs` — `BitmapCacheRev2CapabilitySet`, `BitmapCacheCellInfo`,
  `GlyphCacheCapabilitySet`, `ORDER_NEG_INDEX_INDEX`, `ORDER_NEG_DSTBLT_INDEX`,
  `ORDER_NEG_PATBLT_INDEX`, `ORDER_NEG_MULTIOPAQUERECT_INDEX`, `ORDER_NEG_POLYLINE_INDEX`,
  `ORDER_NEG_SCRBLT_INDEX`,
  `ORDER_NEG_MEMBLT_INDEX`, `ORDER_NEG_MEM3BLT_INDEX`,
  `BITMAP_CACHE_REV2_MAX_ENTRIES`, `ORDER_FLAGS_EXTRA_FLAGS`,
  `ORDERFLAGS_EX_ALTSEC_FRAME_MARKER_SUPPORT`
- `justrdp-codecs/src/rop.rs` — `rop3`, `uses_pattern`, `Pattern`, `pattern_rows`,
  `HATCH_PATTERNS`
- `justrdp/src/orders.rs` — `Orders`, `clip_blt`, `compose`, `pattern`, `order_color`,
  `MAX_HELD_RECTS`
- `justrdp/src/advertise.rs` — `HONOURED_ORDERS`, `HONOURED_ORDER_FLAGS`,
  `HONOURED_BITMAP_CACHE_REV2_FLAGS`, `HONOURED_ORDER_EX_FLAGS`, `check_orders`
- `justrdp/src/session.rs` — `apply_orders`, `on_demand_active`, `ServerAnnouncement`,
  `decode_bitmap`, `charge`
- `justrdp/tests/real_server_memblt.rs` — `a_real_desktop_painted_in_memblt_orders_replays`
- `justrdp-tokio/src/lib.rs` — `memblt_orders_paint_the_desktop_on_the_real_vm`,
  `scrblt_slides_the_start_menu_as_a_redraw_paints_it_on_the_real_vm`,
  `frame_markers_bracket_what_a_redraw_paints_on_the_real_vm`,
  `bitmap_cache_order_sessions_are_not_reset_on_the_real_vm`,
  `orders_at_32_bpp_paint_what_a_redraw_paints_on_the_real_vm`, `orders_at_depth`, `OrderCensus`,
  `legacy_orders_config`
- `fuzz/fuzz_targets/orders.rs`, `fuzz/fuzz_targets/session_orders.rs`

## Reference behaviour

**The census (#22, 2026-10-15).** FreeRDP 3.32.1 against the WS2019 VM, every cache advertised:

- **Orders are gated by the bitmap cache, not by `orderSupport`.** With orders advertised and no
  bitmap cache, the server painted in Surface Commands and sent no order.
- **At 24 and 32 bpp FreeRDP's bitmap cache advertisement got the connection reset** 11 ms
  after activation, after two Frame Markers, with no Set Error Info; at 16 bpp it works. Still
  so on 2026-10-16. Something FreeRDP-specific triggers it, not the depth: see #463 below.
- **What a 68 s interactive 16 bpp session carried:** 21,096 MemBlt and 159 ScrBlt, all
  SRCCOPY; 16,388 Cache Bitmap (Revision 2); 1,294 Frame Markers; no other order, and no glyph
  order with `GLYPH_SUPPORT_FULL` advertised and text typed.

**A second census: xrdp 0.9.24 (2026-10-16).** FreeRDP 3.32.1 against the xrdp server
([Verification harness](verification-harness.md)), every cache advertised:

- **The logged-in Xorg desktop paints like WS2019**: in 40 s at 16 bpp, 11,047 MemBlt (all
  SRCCOPY) and 782 Cache Bitmap V2, and no other order.
- **The login screen, which xrdp draws itself, is where the other orders are**: 46 OpaqueRect, 33
  Cache Glyph, 16 GlyphIndex and 8 PatBlt (all PATCOPY). The counts are the same at 16, 24 and
  32 bpp. At 8 bpp there is also 1 Cache Color Table, as on the 8 bpp desktop (5,024 MemBlt and
  350 Cache Bitmap V2 in 20 s).
- **Sent by neither of these two servers**: DstBlt, LineTo, the Multi* orders, polygons,
  ellipses, SaveBitmap, Cache Brush, the offscreen orders and Cache Bitmap revisions 1 and 3.
  xrdp has encoders for several of them (`libxrdp/xrdp_orders.c`), and none appeared. The third
  census below found several.

**A third census: Windows Server 2008 R2 (#22, 2026-10-16).** FreeRDP 3.32.1 against the GDI
orders VM ([Verification harness](verification-harness.md)) with `/sec:rdp`, every cache
advertised, 180 s of mspaint shapes, window drags and Explorer: 96,442 Frame Marker, 90,006
MemBlt, 71,080 OpaqueRect, 22,095 compressed and 47 uncompressed Cache Bitmap V2, 11,652
MultiOpaqueRect, 4,858 Switch Surface, 1,280 Create Offscreen Bitmap, 1,280 DstBlt (all
BLACKNESS), 1,064 FastGlyph, 535 ScrBlt (all SRCCOPY), 241 PatBlt (178 PATCOPY, 63 PATINVERT),
114 Polyline, 49 Mem3Blt (rop 0xB8) and 3 Cache Brush. A 20 s logon with no input already
carried every kind but ScrBlt, Polyline, Mem3Blt and the uncompressed Cache Bitmap. mspaint's
shapes arrived as MemBlt; no LineTo, polygon or ellipse came.

**Its logon screen in orders against bitmaps (#484, 2026-10-19).** justrdp advertising every
order the core honours, over a TLS-only session that sends no password, received 382 MemBlt
(SRCCOPY), 2 OpaqueRect and 49 Cache Bitmap (Revision 2), and the screen equals the same screen
in bitmap updates with no pixel differing
(`the_gdi_orders_vm_paints_its_logon_screen_in_orders_as_in_bitmaps`). The bitmap screen is the
same in two sessions, and a session naming another user moves 288 pixels of it, all on the
user tile. The logged-in desktop under the same advertisement, read until it went quiet, carried
616 MemBlt, 33 OpaqueRect and 69 Cache Bitmap, and no order it did not advertise
(`the_gdi_orders_vm_paints_its_desktop_in_orders`). That session was idle, and justrdp advertises
none of the orders this server is the only source of. FreeRDP, which advertises them, got them
on the logon screen too: a TLS-only session with an empty password, 25 s, received 1,498
OpaqueRect, 576 FastGlyph, 255 MemBlt, 35 Switch Surface, 10 Create Offscreen Bitmap, 10 DstBlt,
4 MultiOpaqueRect, 2 PatBlt and 1 Cache Brush (2026-10-19). An empty password may have taken it
through the failed-logon screen rather than the one the tests compare, which was not checked.

**xrdp's login screen in orders against bitmaps (#475, #476, 2026-10-16).** A session
advertising DstBlt, PatBlt, ScrBlt, MemBlt, Mem3Blt and GlyphIndex over FreeRDP's ten default
glyph caches received 72 OpaqueRect, 2 PatBlt (PATINVERT, solid), 12 MemBlt over 12 Cache Bitmap
(Revision 2), 33 Cache Glyph into cache 7 and 9 GlyphIndex, and no update ended early. A session
advertising no order got the same screen in bitmap updates. Without the glyphs (#475) the two
differed in 1,241 pixels, all inside the GlyphIndex text rectangles; with them (#476) they differ
in none (`xrdp_paints_its_login_screen_in_orders_as_in_bitmaps`). At 8 bpp (#477) the order
session got the same orders over 9 Cache Bitmap (Revision 2) at 8 bpp, a Palette Update and a
Cache Color Table, and differs from the 8 bpp bitmap screen (28 colours) in none either
(`…_at_8_bpp`). The bitmap screen never passes
through the order decoder, the fills or the glyphs, so for those it is independent; the logo's
tiles decode through the same bitmap codecs in both sessions, so for them it is not.

**Offscreen bitmaps on the 2008 R2 VM (#489, 2026-10-19).** A throwaway probe, never committed,
advertised justrdp's orders and an offscreen cache:

| Session | Creates | Ids | Largest | Peak live, 16 bpp |
|---|---|---|---|---|
| Logon screen, 7,680 KB | 10 | 0–2 | 1280×800 | 2,133 KB |
| Logon screen, 512 KB | 9 | 0–2 | 1280×36 | 223 KB |
| Desktop, 7,680 KB | 49 | 0–3 | 1280×800 | 4,023 KB |

- **The server keeps to the advertised size.**
- **What it draws on offscreen bitmaps:** OpaqueRect, GlyphIndex, MemBlt (from the bitmap cache and
  from another offscreen bitmap), DstBlt, MultiOpaqueRect and PatBlt.
- **Never seen:** delete lists, and ScrBlt onto an offscreen target.
- **Text arrives as GlyphIndex, not FastGlyph**, with offscreen advertised.

With the cache built, the logon screen in orders (10 Create Offscreen Bitmap, 29 Switch Surface,
25 MemBlt from offscreen, 744 OpaqueRect, 288 GlyphIndex, 10 DstBlt, 1 MultiOpaqueRect) equals the
bitmap screen with no pixel differing (`the_gdi_orders_vm_paints_its_logon_screen_in_orders_as_in_bitmaps`).
A MemBlt from offscreen that misses moves 11,169 pixels of it.

**What sends Polyline on the 2008 R2 VM (#488, 2026-10-19).** FreeRDP, every order advertised,
one untimed session per action, the maintainer acting:

| Action | Polyline |
|---|---|
| Drawing in mspaint (pencil, line, curve) | 8 |
| Moving, resizing and minimising windows | 1,068 |
| Moving a window by its title bar only | 52 |
| Resizing a window only | 752 |

So resizing a window sends them; mspaint's shapes arrive as MemBlt. An earlier set of timed
sessions, too short to act in, was discarded. Three attempts to drive a resize from a justrdp
test did not get one: a session reattached to one already open, a keyboard resize (Alt+Space,
Size) that opened Internet Explorer from the Initial Configuration Tasks window instead, and a
mouse drag on that window's right edge that did not move it. One of those sessions (the
reattached one) brought 8 Polyline (`bRop2` 13, COPYPEN).

**justrdp's own advertisement (#460):** MemBlt and Mem3Blt, caches of 120, 120 and 2553 entries,
no waiting list, 16 bpp, no Surface Commands. The server sent only compressed 16 bpp Cache Bitmap
(Revision 2) into cache 2 and SRCCOPY MemBlt, on the fast path; the fixture
(`justrdp/tests/fixtures/session/memblt.bin`) holds 39 Orders updates and 1,495 MemBlt, and its
replay equals the live framebuffer.

**ScrBlt against a redraw (#461).** Advertising ScrBlt beside MemBlt and Mem3Blt:

- **This server sends ScrBlt only for a LAN experience, and then for menu animation.** With
  `VALID_CONNECTION_TYPE` and LAN, opening the Start menu slid it up in 7 SRCCOPY ScrBlts of about
  648×624, each 1–4 rows from its source, so every one overlaps it; the same in two runs. Without
  the connection type (`performanceFlags` 0x7, which this server honours then) no menu animates.
  A Notepad window moved with the keyboard, and Notepad text scrolled by typing past its last
  line, were painted in MemBlt in four runs out of five; the fifth brought 2 ScrBlt whose
  geometry was not recorded. FreeRDP's 159 were in a LAN session with a person moving windows
  and scrolling Explorer, so which of those actions sent them is not known.
- **The framebuffer after the slide equals, byte for byte, the one the server paints for a
  Refresh Rect of the whole desktop.** It is the server's own redraw, so it is the oracle rather
  than a capture, and no fixture was committed. Copying the overlap in place bottom-up makes
  109,040 pixels differ, so the comparison sees a wrong copy order. The slide copies upward
  only; the other three directions rest on the unit test.

**Frame Markers (#462).** Advertising `ORDERFLAGS_EX_ALTSEC_FRAME_MARKER_SUPPORT` (with
`ORDERFLAGS_EXTRA_FLAGS`) beside ScrBlt, MemBlt and Mem3Blt, a logon and the Start menu came in
38 started and 38 ended frames; 1,239 blits reached the host as 151 frame updates, and the
desktop equalled a Refresh Rect redraw; every pixel the Start click changed lay in a rect the
host was handed. Handing every rect over at once makes it 1,488 as 1,488 on the same run, so the
count sees the holding; releasing nothing at the end leaves the logon unpainted for the host, and
the run fails before its first assertion, at the wait for the desktop. The pixel comparison
alone could see neither: holding never touches the framebuffer.

**Order sessions at 32 bpp (#463).** justrdp's bitmap-cache order advertisement is not reset
at any depth: 32 bpp, 24 bpp (which this VM's colour-depth policy answers with 32) and 16 bpp,
and at 32 bpp with the waiting list, with FreeRDP's five cells (600, 600, 2048, 4096, 2048) and
with Frame Marker, each in its own connection, orders arriving in every one
(`bitmap_cache_order_sessions_are_not_reset_on_the_real_vm`). Measured once, not in a test: a
throwaway build that lifted the advertisement check added FreeRDP's other differences one at a
time at 32 bpp, and none reset either: its whole `orderSupport` (MemBlt V2 indices, OpaqueRect,
LineTo, Polyline and the rest), `COLORINDEXSUPPORT`, both together, Frame Acknowledge 2, Large
Pointer, its five plain sets (Share, Font, Control, Color Cache, Window Activation), Surface
Commands, and `drawingFlags` 0x0A. **What resets FreeRDP is not identified.** Not tried: FreeRDP's
Glyph, Offscreen, Brush, Bitmap Codecs, Input, Pointer and Virtual Channel sets as it fills them,
its GCC blocks and Client Info, combinations of the above, and what it sends after activation.
Nothing measured says FreeRDP's input is wrong rather than one the server mishandles.

A 32 bpp session caches 32 bpp bitmaps (compressed, so RDP6 planar), and its desktop equals a
Refresh Rect redraw. That redraw goes through the same decoder, so it cannot see a decode fault;
what can is a 32 bpp NSCodec session's desktop, an independent decoder. Measured once, from the
two tests' dumps (`justrdp-463-32bpp.ppm`, `justrdp-150-nscodec-surface-bits.ppm`): 4,064 pixels
differ by at most 21 per channel, which is NSCodec's loss, and 1,996 differ by more, all in two
40-row cells where the content itself differs, the Start button's highlight and the clock. In
both dumps the "activate Windows" watermark's region (880–1279 × 640–739) is all black, where
every 16 bpp dump draws the watermark: at 32 bpp the server does not paint it.

**Two readings settled by the tie-break, neither reachable from this VM's traffic:**

- **TS_COLOR at 15 and 16 bpp is the pixel**, its first two bytes little-endian, as FreeRDP's
  `update_read_color` and `gdi_decode_color` read it; 2.2.2.2.1.1.1.8 says red, green, blue for
  every RGB depth. At 24 and 32 bpp the spec's red, green, blue is kept.
- **A pattern brush's rows follow the spec's example**: `BrushExtra` holds the top seven rows,
  penultimate first, and `BrushHatch` the bottom one (2.2.2.2.1.1.2.3). FreeRDP's
  `update_read_brush` stores the hatch byte as row 0, a one-row rotation of the spec.

**What the replay cannot tell apart:** every MemBlt this server sent used its source's full
height, so reading `nYSrc` inverted, as the spec's formula does, replays identically (measured by
mutation); the top-down reading rests on FreeRDP and the unit tests.

## Cross-cutting invariants

- [What we advertise, we must implement](../invariant/what-we-advertise-we-must-implement.md) —
  the Revision 2 cache's Mem3Blt obligation, and every row `check_orders` holds.
- [Capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md)
  — the census had to go through FreeRDP because justrdp could not advertise orders, and the
  bitmap cache, not `orderSupport`, is what made the server send them.
- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) — the order
  decoder and the paint path, each with a proptest and a fuzz target.

## Blast radius

- [Capability exchange & activation](capability-exchange-activation.md) — the Order and Revision 2
  rows of the allow-list, and the rules between sets.
- [Session loop & PDU dispatch](session-loop-dispatch.md) — the Orders Update branches on both
  transports, the paint budget, and the reactivation reset.
- [Framebuffer & frame delivery](framebuffer-frame-delivery.md) — one `FrameUpdate` per painted
  order, through `Framebuffer::blit`.
- [Bitmap codecs](bitmap-codecs.md) — cache fills decode through the interleaved RLE and planar
  decoders the bitmap update path uses (`decode_bitmap`).
- [Verification harness](verification-harness.md) — the FreeRDP census procedure and the VM's
  colour-depth dependence.
- [Adapter drive loop](adapter-drive-loop.md) — the runners release an order frame left open.

## Known holes / open

- **Unbuilt:** LineTo, MultiDstBlt, MultiPatBlt, MultiScrBlt, polygons, ellipses, SaveBitmap,
  FastIndex and FastGlyph, Cache Glyph Revision 2, glyph fragments, Cache Brush, Cache Bitmap
  revisions 1 and 3, and every alternate secondary order but Frame Marker, Switch Surface and
  Create Offscreen Bitmap. The 2008 R2 VM sends FastGlyph to a client advertising it (#486, which
  saves only bandwidth, since that server sends GlyphIndex otherwise); no measured server sent
  the rest.
- **Cache Brush is not built, the maintainer's call** (#487, 2026-10-19). Advertised at either
  colour level, the 2008 R2 VM sent one mono brush, used by PatBlt, and no colour brush. Without
  the brush set it sends the same brushes inline, which already paint. Caching would save 8 bytes
  a brush, and the only level that turns it on also advertises colour brushes no server has sent.
- **Polyline's painting is untested against a server** (#488). Its decoding is proven against
  the spec's example; its pixels follow FreeRDP's line rule, read from `gdi_LineTo`, in tests
  derived from that reading. The one server that sends it does so on a window resize, which no
  justrdp test has yet driven.
- **The Offscreen Bitmap Cache Error PDU is proven only by unit tests**: the measured server
  keeps to the advertised size, so nothing real reaches it.
- **Glyph advances by `ulCharInc`, vertical and reversed text are proven only against the spec**:
  xrdp's text is horizontal with per-glyph deltas.
- **DstBlt's real-server proof is BLACKNESS on an offscreen bitmap** (#489): the 2008 R2 logon
  screen's ten, inside its comparison. Its other three ROPs are proven against the spec and
  FreeRDP only.
- **The defaults do not advertise orders**, at any depth; that stays the host's choice (the
  maintainer's call of 2026-10-16, made before #463's measurement for either outcome, and the
  outcome was that 32 bpp order sessions work).
- **A server whose colour tables differ from its palette would paint wrong at 8 bpp**, and say so
  in the log. None is known; the spec's way is what such a server would need.
- **Below 8 bpp** is refused, unmeasured.
- **The 8 bpp proof is the login screen**, 9 cache bitmaps; the logged-in desktop, which FreeRDP's
  census saw carry 5,024 MemBlt at 8 bpp, needs a logon justrdp cannot make on TLS-only security
  without a password, and was not compared.
- **Persistent bitmap caching** (keys, the Persistent Key List PDU) is refused at the
  advertisement and stays on #28.
