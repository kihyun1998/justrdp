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

## Code

- `justrdp/src/egfx.rs` — `Surface`, `CachedBitmap` (`mapped`, `dirty`)
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
  — surface allocation is `width × height × 4`.
- [Capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md)
  — the Progressive quality ladder only appears if the client asks for a slow link.
- [A later stage can hide an earlier defect](../invariant/a-later-stage-can-hide-an-earlier-defect.md)

## Blast radius

- [Bitmap codecs](bitmap-codecs.md) — wire-to-surface payloads are codec streams;
  the Progressive rewrite moves work across this boundary.
- [Framebuffer & frame delivery](framebuffer-frame-delivery.md) — the blit target.
- [Virtual channels](virtual-channels.md) — the EGFX channel's framing, chunking and
  lifecycle.
- [MCS / GCC channel setup](mcs-gcc-channel-setup.md) — the `0x0100` early flag is
  the on/off switch for this whole territory.
- [Capability exchange & activation](capability-exchange-activation.md) — surface
  commands and frame-ack are capability-gated.

## Known holes / open

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
- H.264 / AVC420 / AVC444 (epic #21) is absent — no oracle exists for it either
  (ADR-0002's amendment says so explicitly).
- Surface-to-surface and surface-to-cache commands are implemented against one
  server's behaviour; the VM's advertised cap set bounds what has ever been
  exercised.
