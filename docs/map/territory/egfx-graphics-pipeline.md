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

## Design model

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
  `dirty`, `frame_paint`), `MAX_SURFACE_DIM`, `MAX_TOTAL_SURFACE_BYTES`, `note_budget`
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
- Spec sections cited inline: `[MS-RDPEGFX]` 2.2.2.14, 3.3.8.2

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
  #263 left it alone rather than filing it. **A `## Deliberate divergences` row is owed**;
  that table is owned by [`docs/agents/thegraph.md`](../../agents/thegraph.md) and only a
  `/grill-the-graph` run may write it, so it is recorded here in the meantime.

- **A second `## Deliberate divergences` row is owed, and this one is load-bearing for a
  decision rather than for a tolerance nobody pays for** (#268). justrdp **skips** the entries
  past a per-frame paint budget and keeps both the channel and the session. **FreeRDP** closes
  the graphics channel on a failed graphics command — `drdynvc_main.c`, `if (status !=
  CHANNEL_RC_OK) status = dvcman_channel_close(...)`, introduced deliberately in `17e0d251`
  (2020-03-04) *"as expected by Microsoft's windows protocols test suite"*. **IronRDP** does not
  bound the count at all, and its compositor paint operations are infallible (`-> ()`), so it
  has no place to put a refusal even if it wanted one. **Microsoft's own conformance suite**
  expects a whole-connection drop for a *structurally inconsistent* graphics command but
  expects *tolerate and acknowledge the frame* for a `CACHE_TO_SURFACE` naming a nonexistent
  cache slot — and **an over-budget count is well-formed**, which puts it on the tolerate side
  of Microsoft's own line. That is the argument for skip rather than refuse, and it is recorded
  nowhere else. Two siblings bound how much this could be got wrong: **#270** (which DVC errors
  should close a channel versus drop the connection — every one drops it today, so "refuse"
  here would have cost the whole session, not the channel) and **#271**, whose premise this territory
  carried and which is now **false**: the ladder reached only `CAPVERSION_10`, so the spec's
  own channel-reset mechanism was unreachable from here. It reaches **10.4** as of #271, and
  3.3.5.19 makes the reset available from 10.3 upward — so the cheapest rung of that ladder
  exists now, though nothing sends it yet (the reset itself is a sibling: neither reference
  client implements it, and a probe showed this server honours a mid-session re-advertise and
  then drops the connection when the client does not hold up 3.3.5.19's two MUSTs).

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
