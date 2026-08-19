# EGFX graphics pipeline

## What it is

The modern graphics path (`[MS-RDPEGFX]`), carried over the
`Microsoft::Windows::RDS::Graphics` dynamic virtual channel: the server creates
off-screen **surfaces**, fills them with codec-compressed wire-to-surface commands,
maps them to output positions, keeps a bitmap **cache**, and expects the client to
acknowledge frames. It is server→client only, and it is reachable only if
`SUPPORT_DYN_VC_GFX_PROTOCOL` was set back at GCC.

## Governing decisions

- [ADR-0003](../../adr/0003-phased-codecs-differential-oracle.md) — the EGFX
  decoders (zgfx, RemoteFX Progressive) are the ones still on the phase-1
  `egfx-bootstrap` wrapper, so this territory is where the phased-ownership plan is
  visibly unfinished (epic #158).
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
- `justrdp-codecs/src/egfx.rs` — `Zgfx` (behind the `egfx-bootstrap` feature — the
  last phase-1 wrapper; Progressive left it in #172)
- `justrdp-codecs/src/rfx/progressive.rs` — `Progressive`, `PaintedRect`,
  `PayloadOutcome`, `SurfaceStore` (self-owned, ungated, live since #172)
- `justrdp-codecs/src/capture.rs` — `progressive_capture_dir`, `progressive_payload`
  (the real-server corpus harness, ungated so it does not ride zgfx's feature flag)
- Spec sections cited inline: `[MS-RDPEGFX]` 2.2.2.14, 3.3.8.2

## Reference behaviour

**None.** No verified external-fact store. Note that this is the territory whose
phase-2 rewrite (epic #158) *depends* on a reference comparison — the oracle is
`ironrdp-graphics`, and its shared lineage is itself an invariant below.

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

- **zgfx alone is still an `ironrdp-graphics` wrapper** behind `egfx-bootstrap`; #189 is
  its rewrite. Epic #158 (slices #167–#172) closed the Progressive half: the self-owned
  decoder (`justrdp_codecs::rfx::progressive::Progressive`) is the **live** WTS2 decoder as
  of #172, so this territory no longer holds two decoders that disagree about the picture.
  What the swap changed on the wire-visible side: a tile is now painted only where its
  region's rects reach — a measured 57 386-pixel difference over one captured
  1 280 x 800 session — and the per-tile `Vec<u8>` the bootstrap wrapper returned is gone,
  which is 6193 x 16 KiB of allocation per session that
  [the frame path carries no owned pixels](../invariant/frame-path-carries-no-owned-pixels.md)
  never reached because it stopped at the surface→framebuffer step.
  **A consequence that is easy to miss: an
  oracle bump is a *live-path* change for zgfx**, not only a test change — the
  0.8 → 0.9 move (#184/#186) shipped Devolutions/IronRDP#1395, which stops Progressive
  requiring a `WBT_CONTEXT` block on every frame once a context exists. #170's self-owned
  lifecycle reproduces it and then some: `order_payload` never gates a region on a context
  block at all, which is FreeRDP's rule and the one the real server needs (51 of its 52
  payloads carry no `CONTEXT`).
- H.264 / AVC420 / AVC444 (epic #21) is absent — no oracle exists for it either
  (ADR-0002's amendment says so explicitly).
- Surface-to-surface and surface-to-cache commands are implemented against one
  server's behaviour; the VM's advertised cap set bounds what has ever been
  exercised.
