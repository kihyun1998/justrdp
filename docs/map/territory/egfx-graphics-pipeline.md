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
  `dirty`), `MAX_SURFACE_DIM`, `MAX_TOTAL_SURFACE_BYTES`
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
- H.264 / AVC420 / AVC444 (epic #21) is absent — no oracle exists for it either
  (ADR-0002's amendment says so explicitly).
- Surface-to-surface and surface-to-cache commands are implemented against one
  server's behaviour; the VM's advertised cap set bounds what has ever been
  exercised.
