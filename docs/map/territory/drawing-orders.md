# Drawing orders

## What it is

The GDI drawing orders of `[MS-RDPEGDI]`: compact paint commands a server sends in an Orders
Update on either transport, decoded against a history of the previous orders, painting from caches
the server fills. What is built is the bitmap cache path and nothing else, because it is what the
test VM sends: Cache Bitmap (Revision 2) fills a Revision 2 bitmap cache, and MemBlt and Mem3Blt
blit from it with a ROP3, Mem3Blt through an 8×8 brush. `justrdp-pdu::orders` holds the wire
format, `justrdp-codecs::rop` the raster operations and brushes, and `justrdp::orders` the caches
and the paint. ScrBlt copies within the framebuffer (#461), and Frame Markers bracket what the
host is handed as one frame (#462). Epic #22 (the bitmap cache half is
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
- **A cache holds bitmaps up to its tile size**, `16 << cacheId` on each side (3.1.1.1.1), so a
  cache's decoded size is bounded by the host's entry counts. A larger fill is refused and its
  entry emptied, so a later MemBlt misses rather than painting the bitmap that was there before.
  The budget does the same: past it a fill empties its entry.
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
  bound. It accepts the stall the Graphics Pipeline already accepts, a start whose end never
  comes; it did not decide whether either should get a bound, nor the Surface Commands frame
  marker, a different message.
- **Unmatched markers are tolerated**, in ADR-0009's posture; §2's enumeration names no
  sequencing fault, so this is a reading of it rather than its text. A start inside a frame
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
  Demand Active, the client's Bitmap set only when that is 0. `check_orders` refuses orders at
  8 bpp on the client's side; a server that answers 8 bpp anyway gets palette-index colours from
  the session palette.
- **Advertising the Revision 2 cache requires MemBlt *and* Mem3Blt.** `[MS-RDPBCGR]`
  2.2.7.1.4.2: a client MUST support both to receive Cache Bitmap (Revision 2). The census saw no
  Mem3Blt, but the obligation is the advertisement's, so the brush path is built.

## Code

- `justrdp-pdu/src/orders.rs` — `decode_order`, `OrderHistory`, `OrdersUpdate`, `DrawingOrder`,
  `Clip`, `ScrBlt`, `MemBlt`, `Mem3Blt`, `Brush`, `CacheBitmapRev2`, `OrderError`,
  `TS_ALTSEC_FRAME_MARKER`
- `justrdp-pdu/src/capability.rs` — `BitmapCacheRev2CapabilitySet`, `BitmapCacheCellInfo`,
  `ORDER_NEG_SCRBLT_INDEX`, `ORDER_NEG_MEMBLT_INDEX`, `ORDER_NEG_MEM3BLT_INDEX`,
  `BITMAP_CACHE_REV2_MAX_ENTRIES`, `ORDER_FLAGS_EXTRA_FLAGS`,
  `ORDERFLAGS_EX_ALTSEC_FRAME_MARKER_SUPPORT`
- `justrdp-codecs/src/rop.rs` — `rop3`, `uses_pattern`, `Pattern`, `pattern_rows`,
  `HATCH_PATTERNS`
- `justrdp/src/orders.rs` — `Orders`, `clip_blt`, `compose`, `order_color`, `MAX_HELD_RECTS`
- `justrdp/src/advertise.rs` — `HONOURED_ORDERS`, `HONOURED_ORDER_FLAGS`,
  `HONOURED_BITMAP_CACHE_REV2_FLAGS`, `HONOURED_ORDER_EX_FLAGS`, `check_orders`
- `justrdp/src/session.rs` — `apply_orders`, `on_demand_active`, `ServerAnnouncement`,
  `decode_bitmap`, `charge`
- `justrdp/tests/real_server_memblt.rs` — `a_real_desktop_painted_in_memblt_orders_replays`
- `justrdp-tokio/src/lib.rs` — `memblt_orders_paint_the_desktop_on_the_real_vm`,
  `scrblt_slides_the_start_menu_as_a_redraw_paints_it_on_the_real_vm`,
  `frame_markers_bracket_what_a_redraw_paints_on_the_real_vm`, `OrderCensus`,
  `legacy_orders_config`
- `fuzz/fuzz_targets/orders.rs`, `fuzz/fuzz_targets/session_orders.rs`

## Reference behaviour

**The census (#22, 2026-10-15).** FreeRDP 3.32.1 against the WS2019 VM, every cache advertised:

- **Orders are gated by the bitmap cache, not by `orderSupport`.** With orders advertised and no
  bitmap cache, the server painted in Surface Commands and sent no order.
- **At 24 and 32 bpp a bitmap cache advertisement got the connection reset** 11 ms after
  activation, after two Frame Markers, with no Set Error Info (#463). At 16 bpp it works.
- **What a 68 s interactive 16 bpp session carried:** 21,096 MemBlt and 159 ScrBlt, all
  SRCCOPY; 16,388 Cache Bitmap (Revision 2); 1,294 Frame Markers; no other order, and no glyph
  order with `GLYPH_SUPPORT_FULL` advertised and text typed.

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

## Known holes / open

- **Every order the census saw none of** is unbuilt: DstBlt, PatBlt, OpaqueRect, LineTo, the
  Multi* orders, polygons, ellipses, SaveBitmap, the glyph orders, Cache Color Table, Cache Brush,
  Cache Bitmap revisions 1 and 3, and every alternate secondary order but Frame Marker.
- **24 and 32 bpp** order sessions are unproven (#463); the defaults do not advertise orders.
- **8 bpp** is refused: MemBlt's color table index needs the Color Table Cache.
- **Persistent bitmap caching** (keys, the Persistent Key List PDU) is refused at the
  advertisement and stays on #28.
