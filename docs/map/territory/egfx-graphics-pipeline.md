# EGFX graphics pipeline

## What it is

The modern graphics path (`[MS-RDPEGFX]`), carried over the
`Microsoft::Windows::RDS::Graphics` dynamic virtual channel: the server creates
off-screen **surfaces**, fills them with codec-compressed wire-to-surface commands,
maps them to output positions, keeps a bitmap **cache**, and expects the client to
acknowledge frames. It is server→client only, and it is reachable only if
`SUPPORT_DYN_VC_GFX_PROTOCOL` was set back at GCC.

## Governing decisions

- [ADR-0003](../../adr/0003-phased-codecs-differential-oracle.md) — this territory
  held the phase-1 `egfx-bootstrap` wrappers longest and is where the plan finished:
  Progressive left in #171/#172 (epic #158) and zgfx in #189, which deleted the
  feature. Phase 3 for every decoder here.
- [ADR-0011](../../adr/0011-zero-ironrdp-terminal-state.md) — #189's removal is the
  runtime half of that record reaching its terminal state: no `ironrdp` crate is in
  the runtime graph at all.
- [ADR-0010](../../adr/0010-frameupdate-dirty-rect-contract.md) — surfaces blit
  straight into the framebuffer with no intermediate extract copy (#163).
- [ADR-0009](../../adr/0009-tolerant-negotiation-posture.md) — the 2026-09-16 amendment
  (#286) is where this territory's **deliberate divergences** finally have a home, and it
  carries the first row: `MAX_SURFACE_DIM`.
- [ADR-0015](../../adr/0015-host-chosen-egfx-capabilities.md) — the host picks which honoured
  versions and which cache are advertised (`EgfxConfig`); the core derives each version's flags
  and refuses a version it cannot honour (#273).

## Design model

- **The advertised ladder is the host's narrowing of what the core can honour** (#273).
  `HONOURED_VERSIONS` is the ceiling and the default; `EgfxConfig::versions` picks from it and is
  refused outside it. The host never sets a flag, because which flag a version may carry is a
  per-version fact of 2.2.3: THINCLIENT exists only on 8/8.1, SMALL_CACHE is absent from 10.3
  (small cache implied), and every 10.x needs AVC_DISABLED.
  `EgfxCacheMode::ThinClient` therefore means THINCLIENT on 8/8.1 and SMALL_CACHE above them —
  above 8.1 the 16 MB half of thin-client mode is the only half the wire can carry.
- **10.1 is not honoured** (#296). `[MS-RDPEGFX]` 1.7: *"Usage of the MPEG-4 AVC/H.264 Codec in
  YUV444v2 mode is implied by the RDPGFX_CAPSET_VERSION101 structure"*, and 2.2.3.4 gives it
  sixteen reserved bytes where every other 10.x has the flags word that carries `AVC_DISABLED`. So
  advertising it promises an H.264 decoder this client does not have, with no way to decline.
  #271 put it in the ladder because 1.5.1 names no obligation for it; the obligation is in 1.7.
  Servers read it that way: FreeRDP's shadow server and GNOME Remote Desktop derive AVC444 from
  `!(flags & AVC_DISABLED)`, which is true for 10.1's zero bytes, and `ironrdp-egfx` maps a
  confirmed 10.1 to `avc444: true`. It was unreachable only by ordering — a server picks the highest
  version offered, and 10.2–10.4 were offered beside it — so a server stopping at 10.1 would have
  been the one to send H.264. Removing it also retired the question of `Small` at a confirmed 10.1.
- **The honoured set stops at 10.4 by scope, not by impossibility** (#271). `[MS-RDPEGFX]` 1.5.1
  makes 10.5, 10.6 and 10.7-without-`SCALEDMAP_DISABLE` a MUST to process
  `RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU`, and this client does not. `ironrdp-egfx` advertises
  10.5/10.6 and discharges the MUST without a resampler — it accepts the command, records the
  origin and forwards the target size — and this server's scaled map is 1:1 anyway (measured:
  `target` equals the surface's own 1280x800). Offered the full ladder, the WS2022 VM confirmed
  10.6 and painted zero frames; offered the honoured set it confirms 10.4 and paints. 10.7 *can*
  decline the obligation and is still left out: offered beside 10.4 the same server chose 10.4, so
  nothing measured shows a benefit. The wire order is the one that measurement used and what both
  reference clients send.
- **The Caps Advertise goes out raw.** EGFX segmentation is asymmetric: only server→client traffic
  rides `RDP_SEGMENTED_DATA`. A client→server PDU wrapped in a segment header gets the connection
  reset — measured on the VM, the server reads `0xE0 0x04` as a garbage `cmdId` and ends the
  session, while the raw PDU proceeds to Caps Confirm.
- **The capsets live on the processor and outlive its resets.** `reset_channel` and `close` both
  rebuild from `Default`, so each carries `capsets` across explicitly; forgetting one would make a
  3.3.5.19 reset or a reopened channel silently advertise the default ladder.
- **The bitmap-cache budget is read off the confirm, not off the request** (3.3.1.4): 16 MB at a
  confirmed 10.3 or when the confirm carries THINCLIENT/SMALL_CACHE, 100 MB otherwise. Until #273
  it was 100 MB always, which let a server that stops at 10.3 use six times its budget. FreeRDP
  sizes its slots from its own setting instead (`rdpgfx_main.c`, `MaxCacheSlots`).
- **The slot maximum and the byte budget are one derivation, not two** (#297). 3.3.1.4 pairs
  25 600 slots with the 100 MB cache and 4 096 with the 16 MB one, so `small_cache()` is the single
  predicate and `cache_budget()` / `max_cache_slot()` both read it — two independent readings of
  the confirm could disagree about which cache was confirmed, and nothing would catch it. A slot
  outside the one-based range is warned and skipped ([ADR-0009](../../adr/0009-tolerant-negotiation-posture.md)
  row 4); the check runs **before** the cache lookup, so it never becomes the `Failure::Miss` an
  unfilled in-range slot produces. That ordering is what keeps the two rungs apart, and it is
  pinned by mutation: deleting the `CACHE_TO_SURFACE` guard makes the out-of-range paste take the
  3.3.5.19 reset, and the test reddens.
  **The reset widens both**, and that is inherited rather than chosen: `reset_channel` rebuilds
  from `Default`, so `confirmed_version` goes back to `None` and `small_cache()` is false again
  — a server confirmed at 10.3 gets 100 MB and 25 600 slots for the length of the ignore window,
  until its new confirm narrows them. The byte budget has behaved this way since #273; #297 only
  gave it a second reader.
- **Measured against the WS2022 VM (2026-09-17, #273 probe, 45 s each with mouse sweeps and three
  Start-menu opens):** `EgfxConfig::versions` narrowed to 10.3 confirmed `0x000A0301` flags `0x20`;
  10.4 with `Small` confirmed `0x000A0400` flags `0x22` (the server echoes `SMALL_CACHE`); 8 + 8.1
  with `ThinClient` confirmed `0x00080105` flags `0x01`; the default confirmed 10.4 flags `0x20`.
  Every run stayed up, painted (1571 / 1768 / 1678 / 162 frame updates — the thin-client run's
  RemoteFX updates are fewer and larger), skipped no command, took no reset, and **none hit the
  16 MB budget**. That bounds only this traffic: no run measured peak cache use.

- **A surface is an addressable off-screen buffer with its own dirty list**, and it
  becomes visible only when `MapSurfaceToOutput` gives it an output-space origin.
  Until then, decoded pixels are real but unreachable — a decode bug and a mapping
  bug look identical from the framebuffer.
- **Frame acknowledgement is flow control, not bookkeeping.** A server that
  advertises frame-ack expects it; not sending it stalls the stream rather than
  producing an error.
- **The cache belongs to the connection, not the share** — it survives
  Deactivation–Reactivation, which is stated in the session code and matters here.
- **The EGFX channel is a DVC**, so its framing is the dynamic-channel layer's
  problem, not this territory's.
- **A `destRect` is the bitmap's dimensions, not just where it lands** — `[MS-RDPEGFX]`
  2.2.2.1 says it specifies *"the dimensions (width and height) of the bitmap data
  encapsulated in the bitmapData field"*, and 2.2.1.2 bounds its four `RDPGFX_RECT16`
  fields at `u16` and states nothing else — no maximum, no non-zero requirement, no
  ordering rule. So for every codec that **expands** its input, the rectangle alone
  decides how much memory the decode allocates, and a server picks it. 65535 x 65535 x 4
  is 17_179_344_900 bytes, and #263 measured 93 bytes of TS_RFX buying exactly that.
- **This territory owns the *magnitude* bound for the whole codec family, because it is
  the only one holding a defensible number.** `MAX_TOTAL_SURFACE_BYTES` (256 MiB) is
  *derived*, not picked: `CREATE_SURFACE` refuses when `total_surface_bytes() +
  Surface::bytes(w, h)` passes it, so no single admissible surface exceeds it, and a
  `destRect` is in surface coordinates — a rectangle whose RGBA is larger than every
  surface that can exist names a bitmap nothing could hold. A codec cannot write this
  bound: an *arithmetic* guard there closes only the 32-bit half, and the number that
  would make a magnitude cap principled belongs to the surface model (#263).
- **One number answers two different questions here, and the shared derivation is the reason
  — not the convenience.** `MAX_TOTAL_SURFACE_BYTES` is *also* the **per-frame paint budget**
  (#268). The three list-bearing commands — `SOLID_FILL`, `SURFACE_TO_SURFACE`,
  `CACHE_TO_SURFACE` — each did one unit of surface-clipped pixel work per wire-declared entry
  with nothing bounding the count, so a shape this model already admits (two 5120x5120 surfaces,
  200 MiB of the 256 MiB set, plus a 100 MiB cache entry, each separately legal) turned a fixed
  262 KB PDU into **~505–540 s of `--release` CPU**, returning `Ok`. The magnitude bound asks
  *how much may exist at once*; the work budget asks *how much may happen in one frame*. Both
  answers are **"every surface that could exist, once"** — past that the frame is repainting
  pixels it has already painted this frame — so the two are the same derivation applied to two
  quantities, and a change to the constant moves both. Read the bullet above and this one
  together before touching the number.

  Three properties of the budget are load-bearing and none is obvious from the constant.
  **It is charged on *clipped* bytes**, which is why `Surface::blit` and `Surface::fill` now
  return what they painted: a destination point far off the surface costs nothing and must not
  be charged as if it did — the same tolerance the bullet above declines `is_within_surface` to
  keep, now with a price attached. **It resets at `StartFrame` *and* per message when no frame
  is open**, because nothing in this model requires a frame in order to draw — no arm checks
  `in_frame` before painting — so a server that never sent `StartFrame` would otherwise sit
  outside frame-scoped accounting forever. And **over budget skips the remaining entries and
  returns `Ok`**: the count is well-formed, so there is nothing to raise an error about, and
  the session and the channel both survive. That direction is a divergence from both references
  and from nothing in the spec; see `## Known holes`.

  Sized against the real server rather than against the type: the busiest of 89 measured frames
  painted **4 096 000 bytes — exactly one 1280x800 desktop**, and every `destPtsCount` and
  `fillRectCount` observed was **1**. The ceiling therefore sits ~64x above observed traffic,
  which is the evidence that it bounds an attack and not a server (`docs/plan.md` §0).

- **The bound is deliberately *not* the destination surface's own dimensions**, which is
  tighter and is what FreeRDP does (`is_within_surface`, `gdi/gfx.c:386`, refusing before
  its `1ull * bpp * w * h` at `:390`; `ironrdp-egfx` checks the same condition and only
  `warn!`s). An off-surface rectangle is **clipped** rather than refused, and
  ADR-0009 says not to trade a tolerance we already have for a bound the spec never asked
  for — recorded with the honest caveat that no capture here has ever shown a real server
  sending an off-surface `destRect`, so the tolerance being kept is unobserved too.

  **The tolerance holds at all four surface routines as of #268, and this bullet used to assert
  it from one.** The sentence above read *"a partially off-surface rectangle is clipped by
  `Surface::blit` today"*, which was true — `blit` is the routine the `destRect` path actually
  reaches — and was **read as a statement about the surface model**, because that is what the
  decision it supports is about. `Surface::extract`, which `SURFACE_TO_SURFACE` and
  `SURFACE_TO_CACHE` reach with a `src_rect` taken straight off the wire, clipped `w`/`h` and
  never `x`, and was the one of the four routines without a zero-extent early return: the row
  loop still ran and evaluated `&self.rgba[off..off]` with `off` past the end of the buffer — a
  zero-length slice at an out-of-range **start**, which panics. On an ordinary 1920x1080 surface
  `left == 1920` is the last legal offset and `left == 1921` panicked
  (`range start index 8294404 out of range for slice of length 8294400`), reachable with
  `destPtsCount == 1` and no unusual geometry. **The decision is unchanged and was never in
  doubt** — declining `is_within_surface` costs nothing now that the tolerance is real at every
  site. What was wrong is this record's account of its own coverage, and the way it was wrong is
  the part to carry forward: the claim was checked at one routine and written as if it covered
  the family. Generalised one level out in
  [untrusted decode never panics](../invariant/untrusted-decode-never-panics.md).

## Code

- `justrdp/src/egfx.rs` — `GraphicsProcessor`, `Surface`, `CachedBitmap` (`mapped`,
  `dirty`, `frame_paint`), `MAX_SURFACE_DIM`, `MAX_TOTAL_SURFACE_BYTES`, `note_budget`,
  `Failure`, `can_reset`, `reset_channel`, `caps_advertise`, `small_cache`, `cache_budget`,
  `max_cache_slot`, `cache_slot_out_of_range`, `MAX_CACHE_SLOTS`, `SMALL_CACHE_SLOTS`,
  `EgfxConfig`, `EgfxCacheMode`, `EgfxConfigError`, `HONOURED_VERSIONS`, `ladder`, `capset`
- `justrdp-pdu/src/egfx.rs` — `EgfxPdu`, `Rect16`, `Point16`, `decode_all`,
  `encode_caps_advertise`, `encode_frame_acknowledge`, `wrap_uncompressed`
- `justrdp-codecs/src/zgfx.rs` — `Zgfx`, `ZgfxError`, `History`, `BitReader`,
  `TOKEN_TABLE` (self-owned since #189, which deleted the bootstrap wrapper module
  that used to sit here)
- `justrdp-codecs/src/rfx/progressive.rs` — `Progressive`, `PaintedRect`,
  `PayloadOutcome`, `SurfaceStore` (self-owned, ungated, live since #172)
- `justrdp-codecs/src/capture.rs` — `progressive_capture_dir`, `progressive_payload`
  (the real-server corpus harness; ungated since #172, when it was moved off the
  bootstrap wrapper's feature flag — a flag that no longer exists after #189)
- Spec sections cited inline: `[MS-RDPEGFX]` 2.2.2.6, 2.2.2.7, 2.2.2.8, 2.2.2.14, 2.2.3, 3.3.1.4, 3.3.5.18

## Reference behaviour

**None.** No verified external-fact store. Note that this is the territory whose
phase-2 rewrites (epic #158, then #189) *depended* on a reference comparison — the
oracle is `ironrdp-graphics`, and its shared lineage is itself an invariant below.
zgfx is the one case here where the references supplied a genuinely independent
expectation instead: FreeRDP and `ironrdp-graphics` reproduce the `[MS-RDPEGFX]`
sample byte-identically, so agreeing with it is not agreeing with either of them.

## Cross-cutting invariants

- [What we advertise, we must implement](../invariant/what-we-advertise-we-must-implement.md)
  — **the discovery site (#271)**. The capability version ladder is chosen by which
  obligations this client can discharge, not by how high the version goes: advertising
  through `CAPVERSION_106` made a real server confirm 10.6, send
  `RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT` (`cmdId` 0x0017), and paint **zero** frames with the
  session, the channel and the frame brackets all healthy.
- [Oracle agreement is not independence](../invariant/oracle-agreement-is-not-independence.md)
  — the phase-2 rewrite is verified against a codebase sharing this project's
  lineage.
- [The frame path carries no owned pixels](../invariant/frame-path-carries-no-owned-pixels.md)
  — the surface→framebuffer blit is where the last extract copy was removed (#163).
- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md)
- [Decoder dimension overflow on 32-bit](../invariant/decoder-dimension-overflow-32bit.md)
  — surface allocation is `width × height × 4`, and since #263 so is a
  WireToSurface1 `destRect`. This territory carries the note's *magnitude* half: the
  32-bit `checked_mul` closes the target that already failed loudly, and only a bound on
  the rectangle reaches the 64-bit one, where the product fits and the allocation
  succeeds.
- [Capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md)
  — the Progressive quality ladder only appears if the client asks for a slow link.
- [A later stage can hide an earlier defect](../invariant/a-later-stage-can-hide-an-earlier-defect.md)

## Blast radius

- [Bitmap codecs](bitmap-codecs.md) — wire-to-surface payloads are codec streams;
  the Progressive rewrite moves work across this boundary. **The edge also runs the other
  way, which #263 is what made visible**: the `destRect` bound here is what every codec
  arm's allocation is sized under, so a magnitude hazard in a codec can be closed at this
  layer and a change to `MAX_TOTAL_SURFACE_BYTES` moves what every one of them may be
  asked to decode.
- [Framebuffer & frame delivery](framebuffer-frame-delivery.md) — the blit target.
- [Virtual channels](virtual-channels.md) — the EGFX channel's framing, chunking and
  lifecycle.
- [MCS / GCC channel setup](mcs-gcc-channel-setup.md) — the `0x0100` early flag is
  the on/off switch for this whole territory.
- [Capability exchange & activation](capability-exchange-activation.md) — surface
  commands and frame-ack are capability-gated.

## Known holes / open

- **The cache slot range is bounded as of #297, and this is the evidence the verdict does not
  carry.** The verdict is [ADR-0009](../../adr/0009-tolerant-negotiation-posture.md)'s row 4
  (2026-09-18): out of 3.3.1.4's one-based range is warned and skipped, not refused.
  **Measured here on the WS2022 VM, 2026-09-18**, with throwaway `eprintln!` instrumentation in
  the three cache arms that was never committed — two invocations, four runs, ~45 s of mouse
  sweeps and Start-menu opens each, **9,965 slot observations**:

  | | default | `versions: [CAPVERSION_103]` |
  |---|---|---|
  | confirmed | `0x000a0400` flags `0x20` → 100 MB / 25 600 | `0x000a0301` flags `0x20` → 16 MB / **4 096** |
  | `SURFACE_TO_CACHE` | n=201, slots **2..202** | n=215, slots **2..216** |
  | `CACHE_TO_SURFACE` | n=2 196, slots 2..170 | n=2 197, slots 2..186 |
  | `EVICT_CACHE_ENTRY` | **n=0** | **n=0** |
  | slot 0 / slots > 4 096 | 0 / 0 | 0 / 0 |

  Three things only a measurement could say. **The server does not track the maximum**: slots are
  a plain counter from 2, contiguous and strictly increasing, never reused and never evicted — and
  the *16 MB* run used **more** slots than the 100 MB one, so the number follows session length,
  not the budget. (This bullet first added that a 10.3 session would cross 4 096 in about fifteen
  minutes; it cannot — the byte budget binds first, below, and a 25-minute session reached under
  200 slots, in the bullet after this one.)
  **`EVICT_CACHE_ENTRY` never arrived at all**, so one of the three guarded PDUs is unexercised by
  this server. And **the bound sat ~19x below even the tighter limit**, which is why no
  counterexample appeared and nothing reopened the triage decision — the rung was chosen on the
  first two facts, not on a refusal this traffic could trigger.

  **A fifth run settled the remaining question and corrected the row's first argument.** Entry
  sizes at a confirmed 10.3, 43 entries: exactly two values, **16 384 bytes (64x64 RGBA) and
  8 192 (64x32)** — independently the same shapes #268 measured one issue earlier. Break-even for
  the slot bound to bind before the byte budget is `16 MB / 4 096 = 4 KiB`, and the **smallest**
  entry this server produces is twice that. So **the byte budget always fires first at a confirmed
  10.3** — by slot ~2 048 worst case, ~1 240 at the mean — and the slot bound is unreachable there.
  The rung stands on the normative reading and on the server not tracking the maximum; what this
  changes is that skip over refuse costs nothing measurable against this server.

- **The bitmap cache only grows, and nothing here evicts it — but in 25 minutes it grew to less
  than a fifth of the 16 MB budget.** Falls out of #297's measurements rather than being looked
  for. `SurfaceToCache` removes the entry at the slot it is about to fill, and `EvictCacheEntry`
  removes the slot it names; the server allocates **contiguous, strictly increasing, never-reused**
  slots and has sent **zero** `EVICT_CACHE_ENTRY` in every run here, so neither path fires and
  `cache_bytes` is monotonic. Past `cache_budget()` the `SURFACE_TO_CACHE` arm returns the
  **fatal** refusal (#273), so reaching the budget ends the session.

  **Measured on 2026-09-18, one 25-minute session at a confirmed 10.3** (throwaway
  instrumentation, never committed; mouse sweeps and a Start-menu open/close every ~4 s, 360
  rounds, 63 779 frame updates): the session stayed up until the probe's own timeout, with **no
  fatal and no evict**. The cache was at slot 150 / ~2.25 MiB by the 13-minute mark and ended
  between slot 175 and 199 and **under 3 MiB** — the log kept every 25th slot and each MiB
  crossing, without timestamps, so those are bounds, not a curve. **Growth is front-loaded:** the
  server caches the regions it paints and then pastes them from the cache, so a repeated workload
  plateaus.

  **This corrects the extrapolation #297 first recorded here** — 16 MiB in ~4 minutes at 10.3 and
  ~27 at 100 MB, from the first 45 s's fill rate held constant. The first seconds are the fill;
  holding their rate constant was the error, and the cumulative number was never measured until
  this run. **Still not established:** a long session whose content keeps changing (documents
  scrolled, pages browsed, video) rather than repeating, and what the server does as it nears the
  budget. 3.3.1.4's one MUST is on the server — *"the size of the bitmap data stored across all of
  the in-use variable-length slots at any point in time MUST NOT exceed the total size of the
  cache"* — so evicting before the cap is the server's job, and this server has had no occasion
  to show whether it does it.

- **An inverted `destRect` is silently an empty one, and both references refuse it.**
  `Rect16::width()` is `right.saturating_sub(left)`, so `right < left` yields extent 0 and
  (since #262) `Ok(Vec::new())` — nothing painted, no error. FreeRDP returns
  `ERROR_INVALID_DATA` for it (`channels/rdpgfx/client/rdpgfx_main.c`, checked on the recv
  path before anything else) and `ironrdp-egfx` returns `Err` (`client.rs`, where the
  *ordering* check is its one hard error and the surface-bounds check is only a `warn!`).
  `[MS-RDPEGFX]` 2.2.1.2 states no ordering requirement, so tolerating it is spec-legal —
  but it is a divergence from **both** references with no row recording it, and #262's row
  covers only `right == left`, which is a different case: that one is a legal empty
  rectangle, this one is malformed. Cost of tolerating it is currently zero, which is why
  #263 left it alone rather than filing it. **The note it was owed is written**, in
  [ADR-0009](../../adr/0009-tolerant-negotiation-posture.md)'s 2026-09-16 amendment (#286) as
  row 2 — such notes are owned by the record that decides them, and ADR-0009 is the one for a
  receive-path tolerance. Both reference citations were re-opened at source when it was written.

- **This territory's deliberate divergences have a home, and all four rows are in it.**
  Two bullets here asked for one for months and neither could name a destination.
  [ADR-0009](../../adr/0009-tolerant-negotiation-posture.md)'s 2026-09-16 amendment (#286)
  is it: row 1 the per-axis dimension caps, row 2 the inverted `destRect` (#263), row 3 the
  paint-budget skip (#268), and row 4 the cache-slot range skip (#297, 2026-09-18). **What the two bullets kept is their evidence**, which is the half
  a decision record does not carry — the numbers, the discovery history, and how each claim was
  once wrong. The *verdict* is the ADR's.

- **Row 3, and this one is load-bearing for a
  decision rather than for a tolerance nobody pays for** (#268). justrdp **skips** the entries
  past a per-frame paint budget and keeps both the channel and the session. **FreeRDP** closes
  the graphics channel on a failed graphics command — `drdynvc_main.c`, `if (status !=
  CHANNEL_RC_OK) status = dvcman_channel_close(...)`, introduced deliberately in `17e0d251`
  (2020-03-04) *"as expected by Microsoft's windows protocols test suite"*. **IronRDP** does not
  bound the count at all, and its compositor paint operations are infallible (`-> ()`), so it
  has no place to put a refusal even if it wanted one. **An over-budget count is well-formed**,
  and refusing it would drop a session over a resource ceiling that is ours, not the spec's —
  that is the argument for skip rather than refuse (ADR-0009, 2026-08-31 amendment). This
  bullet used to add that **Microsoft's conformance suite** draws the same line, tolerating a
  `CACHE_TO_SURFACE` naming a nonexistent cache slot. **That was false against the suite's
  code** (#270's enumeration, [ADR-0014](../../adr/0014-dvc-processor-error-posture.md)): the
  test calls its drop-connection helper and only the design document says *"expect a frame
  acknowledge"*, and the helper asserts a drop only under a switch the suite turns off for most
  Windows client versions. The skip stands on the first ground alone. Two siblings bound how much
  this could be got wrong: **#270** (decided by ADR-0014: every processor error still drops the
  connection, attributably, so "refuse" here would have cost the whole session, not the channel)
  and **#271**, whose premise this territory
  carried and which is now **false**: the ladder reached only `CAPVERSION_10`, so the spec's
  own channel-reset mechanism was unreachable from here. It reaches **10.4** as of #271, and
  3.3.5.19 makes the reset available from 10.3 upward — so the cheapest rung of that ladder
  exists now, and #272 sends it on a semantic miss — see the next bullet.

- **The 3.3.5.19 reset is the rung for a semantic miss** (#272,
  [ADR-0014](../../adr/0014-dvc-processor-error-posture.md)'s 2026-09-17 amendment). All
  measured on 2026-09-17 on the WS2022 VM at confirmed **10.4**, with throwaway probes that
  were never committed. Neither reference client ever re-advertises (FreeRDP only in
  `rdpgfx_on_open`, `ironrdp-egfx` only in `start`), so this server is the only evidence.
  - **With both MUSTs held, the session survives: 4/4 sessions**, two short and two with two
    resets each. The client sent the same advertise as `start()`, reset the processor state and
    ignored every decoded PDU until the confirm. The server re-confirmed 10.4, then sent
    `CreateSurface(0, 1280x800)`, `MapSurfaceToOutput`, a run of `DeleteEncodingContext` and a
    full-desktop repaint (245–525 frame updates) onto a framebuffer the probe had zeroed.
    #271's earlier 2/2 disconnects were measured at **10.2**, outside the range 3.3.5.19 grants,
    with the advertise sent and nothing else done, so they are not evidence against the reset.
  - **About one frame is in flight** between the advertise and the confirm: 72 PDUs in two
    messages (a whole `StartFrame`…`EndFrame`), 7 PDUs in one, or none. Ignoring them, including their
    `EndFrame` acknowledgement, cost nothing, as 3.2.5.18 says: the server *"MUST also reset the
    protocol to the initial state and assume that the client has disregarded all the messages
    sent by the server prior to RDPGFX_CAPS_CONFIRM_PDU"*.
  - **The server keeps its zgfx history.** Every post-reset message, in flight and after the
    confirm, was decompressed twice: 0 of 20 came out identical under a fresh `Zgfx`. Lengths
    matched and no error was raised, so a client that resets the history paints **silent
    garbage**. The mutation run (client resets zgfx) happened to trip `RDPGFX_HEADER.pduLength`
    on the first in-flight message and lost the session. So "ignore" means decompress, then
    discard, and a zgfx failure can never be recovered by a reset.
  - **The server resets its ClearCodec state.** Kept against fresh `Clear` over the same payloads:
    54 of 139 and 75 of 175 decodes differed with both sides `Ok`, on V-bar hits (`flags` 0x00),
    glyph stores (0x01) and glyph hits (0x03). The kept caches painted glyph fragments and bars
    across desktop labels, the taskbar and the clock; the fresh ones painted clean. So a reset is
    **not** `close()`'s `*self = GraphicsProcessor::default()`, which also rebuilds zgfx, and it is
    **not** `ResetGraphics`, which frees nothing because that server's encoder keeps its reference
    frames. Three events with three different retention rules.
  - **No real server has produced an error to recover from.** Every `handle` error was logged
    and skipped instead of propagated over four forced-damage sessions: two 120 s (Start menu,
    typed search text, mouse sweeps) and two 170 s (File Explorer and Control Panel, window
    drags, maximise and restore, scrolling, Alt+Tab, six Display Control resizes each,
    `connectionType` LAN and MODEM, 11 269 and 10 360 frame updates). Result: **0** processor
    errors, **0** rung-1 warn-and-skip events, **0** unknown commands, and no multipart zgfx
    message (largest 34 263 bytes). The rung was built anyway, on the maintainer's call (see the
    amendment), so what it recovers from in the field is still unobserved. The census probe
    is the instrument for finding a first instance.
  - **The built rung, live.** A throwaway probe appended a `CacheToSurface` for an unfilled
    slot after decompression; injecting it on the wire would have written bytes the server never
    compressed into the history. The production reset fired, the confirm ended the wait, and
    the session survived 70 s with four more Start-menu cycles (576 frame updates) painting
    clean. The framebuffer is left untouched by the reset, because the full repaint above
    covers it.
  - **Not measured:** Progressive, RemoteFX and planar kept against fresh (not expected to matter;
    see the amendment); any server but this one; any version but 10.4; blob boundaries around the
    confirm (in the two short runs, which logged boundaries, the confirm arrived alone in a
    20-byte message, so per-PDU switching is derived from `decode_all`'s shape, not observed); how
    long stale pixels stay before the repaint; a server that does *not* repaint everything
    after the confirm.

- **Both decoders are self-owned.** zgfx crossed in #189 and epic #158 (slices #167–#172)
  closed the Progressive half: the self-owned
  decoder (`justrdp_codecs::rfx::progressive::Progressive`) is the **live** WTS2 decoder as
  of #172, so this territory no longer holds two decoders that disagree about the picture.
  What the swap changed on the wire-visible side: a tile is now painted only where its
  region's rects reach — a measured 57 386-pixel difference over one captured
  1 280 x 800 session — and the per-tile `Vec<u8>` the bootstrap wrapper returned is gone,
  which is 6193 x 16 KiB of allocation per session that
  [the frame path carries no owned pixels](../invariant/frame-path-carries-no-owned-pixels.md)
  never reached because it stopped at the surface→framebuffer step.
  **An oracle bump is no longer a live-path change for anything in this territory** — that
  used to be true of zgfx and stopped being true in #189, so the
  [oracle-bump table](../invariant/oracle-agreement-is-not-independence.md) has no row-1
  case left. What #189 added instead is the reason a *correct* delegate was still worth
  removing: the delegated decompressor panicked on 5 of 7 crafted messages and the panic
  reached `GraphicsProcessor::process`, because a dependency's decode path cannot appear in
  a fuzz roster derived from `ls fuzz/fuzz_targets/` or in proptests that live in our own
  modules. The 0.8 → 0.9 move (#184/#186) shipped Devolutions/IronRDP#1395, which stops
  Progressive requiring a `WBT_CONTEXT` block on every frame once a context exists; #170's
  self-owned lifecycle reproduces it and then some — `order_payload` never gates a region on
  a context block at all, which is FreeRDP's rule and the one the real server needs (51 of
  its 52 payloads carry no `CONTEXT`).
- **The VM has never sent a multipart zgfx message.** Measured over one session: 25
  messages, every one `ZGFX_SEGMENTED_SINGLE` and `PACKET_COMPRESSED`; the `0xE1`
  descriptor's decode path is proved by the `[MS-RDPEGFX]` sample and the oracle
  differential, not by a real server. Same shape as
  [capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md),
  with no advertised flag to change — a server sends multipart only when a message exceeds
  65535 bytes, and this one's largest was 10 680.
- **The off-surface `destRect` tolerance is not observable, which ADR-0009 §3(b) requires**
  (found sweeping #263). `Surface::blit` clips a rectangle that runs past the surface
  silently — no `tracing` record on the clip path — and #263's bound is argued *on the
  strength of that tolerance being kept* (the alternative, FreeRDP's `is_within_surface`,
  refuses). So the record the posture relies on to justify keeping it is a record nobody
  emits: *"a tolerance you cannot see is indistinguishable from a bug"* is §3(b)'s own
  sentence. Not an ADR-0009 amendment — the rule is right and the code does not follow it —
  and worth a `rdp_egfx` warn naming declared-versus-clipped, which would also be the first
  evidence in this repo about whether a real server ever sends one.

  **#268 widened this hole rather than closing it, and sharpened why it is one.** The clip is
  now silent at four routines instead of three, and the one that was added is the one that
  *panicked* — so for the whole time the tolerance was argued from, `extract` was emitting no
  record of clipping and also not clipping. An unobservable tolerance is not only
  indistinguishable from a bug to a reader; it is indistinguishable from an absent one to the
  test suite, which is the concrete cost §3(b)'s sentence had not yet been charged here.

  **#268's second half moved it, and by less than it looks.** `note_budget` emits the first
  `rdp_egfx` warn in this territory that names *declared versus painted* — which is the shape
  §3(b) has been asking for, and it is exactly the record the bullet above proposed. It fires
  on the **budget** cut, not on the **clip**: a `CACHE_TO_SURFACE` whose points all land off
  the surface still paints nothing, is charged nothing, stays inside budget, and says nothing.
  So the hole is now narrower and sharper rather than closed — the observable case is the one
  where *we* refused work, and the unobservable case is still the one where the *server's*
  geometry was discarded, which is the half that would be evidence about a real server. Closing
  it is a one-line addition at the same four routines and it is deliberately not folded in
  here, because the budget warn and a clip warn answer different questions and a single record
  that fires for both would be unreadable as either.

- H.264 / AVC420 / AVC444 (epic #21) is absent — no oracle exists for it either
  (ADR-0002's amendment says so explicitly).
- Surface-to-surface and surface-to-cache commands are implemented against one
  server's behaviour; the VM's advertised cap set bounds what has ever been
  exercised. **#268 put numbers on how thin that is**, which makes the hole smaller and
  much more precise: over two live 1280x800 sessions this server sent **10**
  `SURFACE_TO_SURFACE` PDUs and **2 748** `CACHE_TO_SURFACE` PDUs, and **every single one
  carried `destPtsCount == 1`** — so the *list* half of these commands has never been
  exercised by a real server at all, at any length above one. Cache entries were **64x64 or
  64x32** and nothing else. Any claim here about multi-point behaviour is derived from the
  spec and from our own tests, never observed; and per
  [capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md)
  even that is one box at one resolution with `connectionType` unrecorded for the run
  (`docs/plan.md` §0).
